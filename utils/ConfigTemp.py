from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    username: str = ""
    password: str = ""
    shared_secret: str = ""
