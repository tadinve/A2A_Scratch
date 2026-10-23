"""Authorization: what is an authenticated identity allowed to do?

The chain is:

    identity -> role -> permissions

and, since Day 04's final increment, the permission an endpoint requires
depends on the resource: reading a class A record needs inventory.read.class_a.

Two separate server-side tables. The caller never supplies its own role or
permissions. Nothing here knows about API keys or SQLite.
"""

# Permission base name. Reading a record of class X requires "inventory.read.class_x".
INVENTORY_READ = "inventory.read"

# Identity -> role. Assigned by the service, not by the caller.
IDENTITY_ROLES = {
    "inventory-agent": "inventory_reader",
    "restricted-agent": "restricted",
}

# Role -> permissions it grants. Kept separate from identities, so access is
# changed by editing a role, never by checking an agent's name in code.
ROLE_PERMISSIONS = {
    "inventory_reader": {
        "inventory.read.class_a",
        "inventory.read.class_b",
        "inventory.read.class_c",
    },
    "restricted": {
        "inventory.read.class_b",
        "inventory.read.class_c",
    },
}


def role_for(identity: str) -> str | None:
    """Return the server-assigned role for an identity, or None if it has none."""
    return IDENTITY_ROLES.get(identity)


def read_permission_for(inventory_class: str) -> str:
    """The permission needed to read a record of this class, e.g. 'inventory.read.class_a'."""
    return f"{INVENTORY_READ}.class_{inventory_class.strip().lower()}"


def is_allowed(role: str | None, permission: str) -> bool:
    """Deny by default: an unknown role, or a role lacking the permission, is denied.

    An unexpected class (say 'D') produces a permission no role grants, so it is denied too.
    """
    if role is None:
        return False
    return permission in ROLE_PERMISSIONS.get(role, set())
