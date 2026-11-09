import contextlib
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from irods.meta import iRODSMeta
from irods.models import User, UserMeta


environment = {key: "test" for key in (
    "DEFAULT_USER_PASSWORD", "LDAP_USER", "LDAP_PASS", "LDAP_HOST",
    "LDAP_USERS_BASE_DN", "LDAP_GROUPS_BASE_DN", "LDAP_COS_BASE_DN",
    "IRODS_HOST", "IRODS_USER", "IRODS_PASS",
)}
environment.update(LOG_LEVEL="CRITICAL", SYNC_USERS="True", DELETE_USERS="True",
                   SYNC_GROUPS="True", DELETE_GROUPS="True")
spec = importlib.util.spec_from_file_location("sram_sync", Path(__file__).with_name("sram-sync.py"))
sync = importlib.util.module_from_spec(spec)
with patch.dict(os.environ, environment):
    spec.loader.exec_module(sync)


class Metadata:
    def __init__(self, avus=()):
        self.avus = [iRODSMeta(*avu) for avu in avus]
        self.writes = []

    def items(self):
        return self.avus.copy()

    def get_all(self, name):
        return [avu for avu in self.avus if avu.name == name]

    def remove(self, avu):
        self.writes.append(("remove", avu.name, avu.value))
        self.avus.remove(avu)

    def add(self, name, value):
        self.writes.append(("add", name, value))
        self.avus.append(iRODSMeta(name, value))

    def __setitem__(self, name, avu):
        self.writes.append(("set", name, avu.value))
        self.avus = [old for old in self.avus if old.name != name] + [avu]


class Query:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *criteria):
        return Query([row for row in self.rows if all(
            row[criterion.query_key] == criterion.value for criterion in criteria
        )])

    def __iter__(self):
        return iter(self.rows)


class Session:
    def __init__(self):
        self.accounts = {}
        self.users = MagicMock()
        self.users.get.side_effect = lambda name, zone=sync.IRODS_ZONE: self.accounts[(name, zone)]
        self.users.create.side_effect = self.add_user
        self.groups = MagicMock()

    def add_user(self, name, user_type="rodsuser", avus=(), zone=sync.IRODS_ZONE):
        user = SimpleNamespace(name=name, type=user_type, zone=zone,
                               id=len(self.accounts) + 1, metadata=Metadata(avus))
        self.accounts[(name, zone)] = user
        return user

    def query(self, *columns):
        rows = []
        for user in self.accounts.values():
            row = {User.name: user.name, User.zone: user.zone, User.type: user.type, User.id: user.id}
            if columns == (User,):
                for avu in user.metadata.items():
                    rows.append(row | {UserMeta.name: avu.name, UserMeta.value: avu.value})
            else:
                rows.append(row)
        return Query(rows)


def ldap_user(uid="alice", unique_id="alice-id", email="alice@example.org"):
    return sync.LdapUser(uid, unique_id, "Alice", email, "Alice", "external-id", "affiliation")


class UserSyncTests(unittest.TestCase):
    def setUp(self):
        self.session = Session()
        self.alice = self.session.add_user("alice", avus=[
            ("email", "alice@example.org"), ("eduPersonUniqueID", "alice-id"),
        ])

    def synchronize(self, users, dry_run=False):
        with patch.object(sync, "get_users_from_ldap", return_value=users):
            return sync.sync_ldap_users_to_irods(None, self.session, dry_run)

    def assert_no_writes(self):
        self.session.users.create.assert_not_called()
        self.session.users.modify.assert_not_called()
        self.assertEqual([], self.session.groups.mock_calls)
        for user in self.session.accounts.values():
            self.assertEqual([], user.metadata.writes)

    def test_active_user_deletion_and_invitation_markers_removed_idempotently(self):
        self.alice.metadata.avus.extend([
            iRODSMeta("pendingDeletionProcedure", "true"),
            iRODSMeta("pendingDeletionProcedure", "true", "another-unit"),
            iRODSMeta("pendingSramInvite", "true"),
        ])
        with patch.object(sync, "DELETE_USERS", False):
            self.synchronize([ldap_user()])
        self.assertEqual([], self.alice.metadata.get_all("pendingDeletionProcedure"))
        self.assertEqual([], self.alice.metadata.get_all("pendingSramInvite"))
        writes = self.alice.metadata.writes.copy()
        self.synchronize([ldap_user()])
        self.assertEqual(writes, self.alice.metadata.writes)

    def test_reinvitation_reuses_original_account_and_updates_unique_id(self):
        self.alice.metadata.avus.append(iRODSMeta("pendingDeletionProcedure", "true"))
        returning = ldap_user("new-uid", "new-id", " ALICE@EXAMPLE.ORG ")
        with patch.object(sync, "invalidate_temporary_password_for_obsolete_users") as invalidate:
            mapping = self.synchronize([returning])
        self.assertEqual({"new-uid": "alice"}, mapping)
        self.assertIs(returning.irods_user, self.alice)
        self.assertEqual("new-id", self.alice.metadata.get_all("eduPersonUniqueID")[0].value)
        self.assertEqual([], self.alice.metadata.get_all("pendingDeletionProcedure"))
        self.session.users.create.assert_not_called()
        self.session.users.modify.assert_not_called()
        self.assertEqual([], self.session.groups.mock_calls)
        invalidate.assert_not_called()

    def test_repeated_email_avus_on_one_account_are_not_ambiguous(self):
        self.alice.metadata.avus.append(iRODSMeta("email", " ALICE@EXAMPLE.ORG ", "other-unit"))
        self.assertEqual({"new-uid": "alice"}, self.synchronize([ldap_user("new-uid")]))

    def test_reinvitation_with_unchanged_unique_id(self):
        self.assertEqual({"new-uid": "alice"}, self.synchronize([ldap_user("new-uid")]))
        self.assertEqual("alice-id", self.alice.metadata.get_all("eduPersonUniqueID")[0].value)

    def test_uid_match_allows_email_change_and_missing_email(self):
        for email in ("new@example.org", ""):
            with self.subTest(email=email):
                self.assertEqual({"ALICE": "alice"}, self.synchronize([ldap_user("ALICE", email=email)]))
                self.assertEqual([email] if email else [],
                                 [avu.value for avu in self.alice.metadata.get_all("email")])

    def test_new_user_created_with_lowercase_name(self):
        mapping = self.synchronize([ldap_user(), ldap_user("BOB", "bob-id", "bob@example.org")])
        self.assertEqual({"alice": "alice", "BOB": "bob"}, mapping)
        self.session.users.create.assert_called_once_with("bob", "rodsuser")
        self.session.users.modify.assert_called_once()
        self.assertEqual("bob", self.session.users.modify.call_args.args[0])
        self.session.groups.get.return_value.addmember.assert_called_once_with("bob")

    def test_missing_email_never_matches_another_account(self):
        mapping = self.synchronize([ldap_user(), ldap_user("bob", "bob-id", "")])
        self.assertEqual("bob", mapping["bob"])
        self.session.users.create.assert_called_once_with("bob", "rodsuser")

    def test_obsolete_users_marked_and_temporary_passwords_invalidated(self):
        invited = self.session.add_user("invited", avus=[("pendingSramInvite", "true")])
        pending = self.session.add_user("pending", avus=[("pendingDeletionProcedure", "true")])
        obsolete = self.session.add_user("obsolete")
        with patch.object(sync, "invalidate_temporary_password_for_obsolete_users") as invalidate:
            self.synchronize([ldap_user()])
        self.assertEqual("true", obsolete.metadata.get_all("pendingDeletionProcedure")[0].value)
        invalidate.assert_called_once_with(["obsolete"])
        self.assertEqual([], invited.metadata.writes)
        self.assertEqual([], pending.metadata.writes)

    def test_dry_run_reports_reinstatement_creation_and_deletion_without_writes(self):
        self.alice.metadata.avus.append(iRODSMeta("pendingDeletionProcedure", "true"))
        self.session.add_user("obsolete")
        with patch.object(sync, "RuleManager") as manager, self.assertLogs(sync.logger, "INFO") as logs:
            mapping = self.synchronize([
                ldap_user("new-uid", "new-id"), ldap_user("BOB", "bob-id", "bob@example.org"),
            ], dry_run=True)
        self.assertEqual({"new-uid": "alice", "BOB": "bob"}, mapping)
        self.assertIn("would remove AVU pendingDeletionProcedure from alice", "\n".join(logs.output))
        self.assertIn("will mark user obsolete for deletion", "\n".join(logs.output))
        self.assert_no_writes()
        manager.assert_not_called()

    def test_conflicts_stop_entire_cycle_before_user_or_group_writes(self):
        cases = (
            "duplicate_irods_email", "duplicate_ldap_email", "shared_account", "shared_new_id",
            "existing_id_owner", "ordinary_uid_changed_id", "missing_uid", "missing_id",
            "protected_email", "protected_uid", "admin_email", "group_uid", "uid_email_disagree",
            "duplicate_ldap_uid", "missing_existing_id",
        )
        for case in cases:
            with self.subTest(case=case):
                self.setUp()
                users = [ldap_user(), ldap_user("bob", "bob-id", "bob@example.org")]
                if case == "duplicate_irods_email":
                    self.session.add_user("duplicate", avus=[("email", " ALICE@EXAMPLE.ORG ")])
                elif case == "duplicate_ldap_email":
                    users[1].email = " ALICE@EXAMPLE.ORG "
                elif case == "shared_account":
                    users[0].email = ""
                    users[1] = ldap_user("returning", "new-id")
                elif case == "shared_new_id":
                    users.extend([ldap_user("carol", "bob-id", "carol@example.org")])
                elif case == "existing_id_owner":
                    self.session.add_user("other", avus=[("eduPersonUniqueID", "bob-id")])
                elif case == "ordinary_uid_changed_id":
                    users[0].unique_id = "changed-id"
                elif case == "missing_uid":
                    users[1].uid = ""
                elif case == "missing_id":
                    users[1].unique_id = ""
                elif case in ("protected_email", "protected_uid"):
                    self.alice.metadata.avus.append(iRODSMeta("ldapSync", "false"))
                    if case == "protected_email":
                        users[0].uid = "returning"
                elif case == "admin_email":
                    self.alice.type = "rodsadmin"
                    users[0].uid = "returning"
                elif case == "group_uid":
                    self.session.add_user("bob", "rodsgroup")
                elif case == "uid_email_disagree":
                    self.session.add_user("bob", avus=[("eduPersonUniqueID", "bob-id")])
                    users[1].email = users[0].email
                    users[0].email = "changed@example.org"
                elif case == "duplicate_ldap_uid":
                    users[1].uid = "ALICE"
                elif case == "missing_existing_id":
                    self.alice.metadata.avus = [iRODSMeta("email", "alice@example.org")]
                with patch.object(sync, "get_users_from_ldap", return_value=users), \
                        patch.object(sync, "get_ldap_connection"), \
                        patch.object(sync, "get_irods_connection", return_value=contextlib.nullcontext(self.session)), \
                        patch.object(sync, "sync_ldap_groups_to_irods") as groups, \
                        patch.object(sync, "RuleManager") as manager:
                    with self.assertRaisesRegex(ValueError, "before making changes"):
                        sync.run(False)
                self.assert_no_writes()
                groups.assert_not_called()
                manager.assert_not_called()

    def test_reinstatement_cannot_claim_id_owned_by_another_account(self):
        self.session.add_user("other", avus=[("eduPersonUniqueID", "new-id")])
        with self.assertRaises(ValueError):
            self.synchronize([ldap_user("returning", "new-id")])
        self.assert_no_writes()

    def test_remote_email_is_not_recovered_and_remote_accounts_are_not_deleted(self):
        remote = self.session.add_user("remote", zone="otherZone", avus=[("email", "bob@example.org")])
        self.synchronize([ldap_user(), ldap_user("bob", "bob-id", "bob@example.org")])
        self.session.users.create.assert_called_once_with("bob", "rodsuser")
        self.assertEqual([], remote.metadata.writes)

    def test_remote_unique_id_collision_is_detected(self):
        self.session.add_user("remote", zone="otherZone", avus=[("eduPersonUniqueID", "bob-id")])
        with self.assertRaises(ValueError):
            self.synchronize([ldap_user(), ldap_user("bob", "bob-id", "bob@example.org")])
        self.assert_no_writes()

    def test_protected_accounts_absent_from_ldap_remain_untouched(self):
        protected = self.session.add_user("service", avus=[("ldapSync", "false")])
        self.synchronize([ldap_user()])
        self.assertEqual([], protected.metadata.writes)

    def test_membership_uses_resolved_username_for_retention_and_addition(self):
        group = sync.LdapGroup("group-id", "co.team.@all", "co.team", "team", ["new-uid"])
        for members in ([self.alice], []):
            with self.subTest(members=bool(members)):
                irods_group = MagicMock(members=members)
                self.session.groups.get.return_value = irods_group
                with patch.object(sync, "get_syncable_irods_groups", return_value={"team"}):
                    sync.sync_group_memberships(self.session, {"co.team": group}, False, {"new-uid": "alice"})
                irods_group.removemember.assert_not_called()
                if members:
                    irods_group.addmember.assert_not_called()
                else:
                    irods_group.addmember.assert_called_once_with("alice")

    def test_dry_run_memberships_never_write(self):
        group = sync.LdapGroup("group-id", "co.team.@all", "co.team", "team", ["new-uid"])
        irods_group = MagicMock(members=[SimpleNamespace(name="obsolete")])
        self.session.groups.get.return_value = irods_group
        with patch.object(sync, "get_syncable_irods_groups", return_value={"team"}):
            sync.sync_group_memberships(self.session, {"co.team": group}, True, {"new-uid": "alice"})
        irods_group.addmember.assert_not_called()
        irods_group.removemember.assert_not_called()

    def test_unresolved_group_members_do_not_remove_existing_members(self):
        group = sync.LdapGroup("group-id", "co.team.@all", "co.team", "team", ["unknown"])
        irods_group = MagicMock(members=[self.alice])
        self.session.groups.get.return_value = irods_group
        with patch.object(sync, "get_syncable_irods_groups", return_value={"team"}):
            sync.sync_group_memberships(self.session, {"co.team": group}, False, {})
        irods_group.addmember.assert_not_called()
        irods_group.removemember.assert_not_called()

    def test_group_member_uid_with_hyphens_is_not_truncated(self):
        self.assertEqual("new-uid", sync.LdapGroup.get_group_member_uids(b"uid=new-uid,ou=People,dc=example"))

if __name__ == "__main__":
    unittest.main()
