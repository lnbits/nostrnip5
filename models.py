import json
from sqlite3 import Row
from typing import List, Optional

from fastapi.param_functions import Query
from lnbits.db import FilterModel, FromRowModel
from pydantic import BaseModel

from .helpers import format_amount, normalize_identifier


class CustomCost(BaseModel):
    bracket: int
    amount: float


class RotateAddressData(BaseModel):
    owner_id: Optional[str] = None
    pubkey: str


class CreateAddressData(BaseModel):
    domain_id: str
    local_part: str
    pubkey: str


class DomainCostConfig(BaseModel):
    enable_custom_cost: bool = False
    char_count_cost: List[CustomCost] = []
    rank_cost: List[CustomCost] = []


class CreateDomainData(BaseModel):
    wallet: str
    currency: str
    cost: float = Query(..., ge=0.01)
    domain: str
    cost_config: Optional[DomainCostConfig] = None


class EditDomainData(BaseModel):
    id: str
    currency: str
    cost: float = Query(..., ge=0.01)
    cost_config: Optional[DomainCostConfig] = None

    @classmethod
    def from_row(cls, row: Row) -> "EditDomainData":
        return cls(**dict(row))


class IdentifierRanking(BaseModel):
    name: str
    rank: int

    @classmethod
    def from_row(cls, row: Row) -> "IdentifierRanking":
        return cls(**dict(row))


class PublicDomain(BaseModel):
    id: str
    currency: str
    cost: float
    domain: str

    @classmethod
    def from_row(cls, row: Row) -> "PublicDomain":
        return cls(**dict(row))


class Domain(PublicDomain):
    wallet: str
    cost_config: DomainCostConfig = DomainCostConfig()
    time: int

    def price_for_identifier(self, identifier: str, rank: Optional[int] = None):
        identifier = normalize_identifier(identifier)
        max_amount = self.cost
        reason = ""
        if not self.cost_config.enable_custom_cost:
            return max_amount

        for char_cost in self.cost_config.char_count_cost:
            if len(identifier) <= char_cost.bracket and max_amount < char_cost.amount:
                max_amount = char_cost.amount
                reason = f"{len(identifier)} characters"

        if not rank:
            return max_amount, reason

        for rank_cost in self.cost_config.rank_cost:
            if rank <= rank_cost.bracket and max_amount < rank_cost.amount:
                max_amount = rank_cost.amount
                reason = f"Top {rank_cost.bracket} identifier"

        return max_amount, reason

    def public_data(self):
        return PublicDomain(**dict(self))

    @classmethod
    def from_row(cls, row: Row) -> "Domain":
        domain = cls(**dict(row))
        if row["cost_extra"]:
            domain.cost_config = DomainCostConfig(**json.loads(row["cost_extra"]))

        return domain


class Address(FromRowModel):
    id: str
    owner_id: Optional[str] = None
    domain_id: str
    local_part: str
    pubkey: str
    active: bool
    time: int

    @classmethod
    def from_row(cls, row: Row) -> "Address":
        return cls(**dict(row))


class AddressStatus(BaseModel):
    identifier: str
    available: bool = False
    reserved: bool = False
    price: Optional[float] = None
    price_reason: Optional[str] = None
    currency: Optional[str] = None

    @property
    def price_formatted(self) -> str:
        if self.available and self.price and self.currency:
            return format_amount(self.price, self.currency)

        return ""


class AddressFilters(FilterModel):
    domain_id: str
    local_part: str
    pubkey: str
    active: bool
    time: int


class Nip5Settings(BaseModel):
    cloudflare_access_token: Optional[str] = None

    @classmethod
    def from_row(cls, row: Row) -> "Nip5Settings":
        return cls(**dict(json.loads(row["settings"])))
