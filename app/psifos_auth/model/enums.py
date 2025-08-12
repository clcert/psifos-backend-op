import enum

class UserRole(str, enum.Enum):
    admin = "admin"
    super_admin = "super_admin"