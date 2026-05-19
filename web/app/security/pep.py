class PolicyEnforcementPoint:
    """Centralized authorization decisions for protected application resources."""

    @staticmethod
    def can_access_admin(actor_role: str) -> bool:
        return actor_role == "admin"

    @staticmethod
    def can_manage_document(*, actor_id: int, actor_role: str, owner_id: int) -> bool:
        return actor_role == "admin" or actor_id == owner_id

    @staticmethod
    def can_upload(actor_role: str) -> bool:
        return actor_role in ("user", "admin")

    @staticmethod
    def can_share_document(actor_role: str) -> bool:
        return actor_role in ("user", "reviewer", "admin")
