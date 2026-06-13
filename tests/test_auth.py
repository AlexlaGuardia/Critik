"""Tests for missing-authentication detection.

Guards both directions: real auth (incl. the modern FastAPI annotation
pattern) must NOT flag, and a genuinely unprotected route MUST flag.
"""

from pathlib import Path

from critik.checks.auth import check_auth


def _names(findings):
    return {f.check_name for f in findings}


def test_annotation_dependency_not_flagged():
    # Modern FastAPI: auth rides in the type annotation, not a default value.
    code = '''
from fastapi import APIRouter, Depends
router = APIRouter()

@router.get("/me")
def read_user_me(current_user: CurrentUser):
    return current_user
'''
    assert "route-no-auth" not in _names(check_auth(Path("r.py"), code, "python"))


def test_annotated_depends_not_flagged():
    code = '''
from fastapi import APIRouter, Depends
from typing import Annotated
router = APIRouter()

@router.get("/items")
def list_items(user: Annotated[User, Depends(get_current_user)]):
    return []
'''
    assert "route-no-auth" not in _names(check_auth(Path("r.py"), code, "python"))


def test_public_route_not_flagged():
    # login is public by definition — flagging it is noise.
    code = '''
from fastapi import APIRouter, Depends
router = APIRouter()

@router.post("/login")
def login_access_token(form_data: OAuth2Form):
    return {"token": "..."}
'''
    assert "route-no-auth" not in _names(check_auth(Path("r.py"), code, "python"))


def test_public_route_stems_not_flagged():
    # register_user / health_check qualify via stem-prefix, not exact name.
    code = '''
from fastapi import APIRouter, Depends
router = APIRouter()

@router.post("/users")
def register_user(user_in: UserRegister):
    return create(user_in)

@router.get("/health")
def health_check():
    return True
'''
    assert "route-no-auth" not in _names(check_auth(Path("r.py"), code, "python"))


def test_genuinely_unprotected_route_flags():
    # A non-public route with no auth at all should still be caught.
    code = '''
from fastapi import APIRouter, Depends
router = APIRouter()

@router.get("/admin/secrets")
def dump_secrets():
    return load_all_secrets()
'''
    assert "route-no-auth" in _names(check_auth(Path("r.py"), code, "python"))
