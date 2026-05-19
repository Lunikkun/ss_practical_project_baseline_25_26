from typing import Any, TypedDict


class UserAuth(TypedDict):
    id: int
    username: str
    password: str
    role: str
    is_disabled: bool


class UserAdmin(TypedDict):
    id: int
    username: str
    role: str
    is_disabled: bool


class UserBasic(TypedDict):
    id: int
    username: str


class DocumentRecord(TypedDict):
    id: int
    owner_id: int
    title: str
    filename: str
    storage_key: str
    metadata: Any
    document_hash: str | None


class DocumentListItem(TypedDict):
    id: int
    title: str
    filename: str
    uploaded_at: Any


class ShareRecipient(TypedDict):
    id: int
    username: str
