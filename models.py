import json
from sqlite3 import Row
from typing import List, Optional, Tuple

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


class UpdateAddressData(BaseModel):
    pubkey: Optional[str] = None
    relays: Optional[List[str]] = None


class CreateAddressData(BaseModel):
    domain_id: str
    local_part: str
    pubkey: str = ""
    years: int = 1
    relays: Optional[List[str]] = None


class DomainCostConfig(BaseModel):
    max_years: int = 1
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

    def price_for_identifier(
        self, identifier: str, years: int, rank: Optional[int] = None
    ) -> Tuple[float, str]:
        assert (
            1 <= years <= self.cost_config.max_years
        ), f"Number of years must be between '1' and '{self.cost_config.max_years}'."

        identifier = normalize_identifier(identifier)
        max_amount = self.cost
        reason = ""
        if not self.cost_config.enable_custom_cost:
            return max_amount * years, reason

        for char_cost in self.cost_config.char_count_cost:
            if len(identifier) <= char_cost.bracket and max_amount < char_cost.amount:
                max_amount = char_cost.amount
                reason = f"{len(identifier)} characters"

        if not rank:
            return max_amount * years, reason

        for rank_cost in self.cost_config.rank_cost:
            if rank <= rank_cost.bracket and max_amount < rank_cost.amount:
                max_amount = rank_cost.amount
                reason = f"Top {rank_cost.bracket} identifier"

        return max_amount * years, reason

    def public_data(self):
        data = dict(PublicDomain(**dict(self)))
        data["max_years"] = self.cost_config.max_years
        return data

    @classmethod
    def from_row(cls, row: Row) -> "Domain":
        domain = cls(**dict(row))
        if row["cost_extra"]:
            domain.cost_config = DomainCostConfig(**json.loads(row["cost_extra"]))

        return domain


class AddressConfig(BaseModel):
    currency: Optional[str] = None
    price: Optional[float] = None
    price_in_sats: Optional[float] = None
    payment_hash: Optional[str] = None
    reimburse_payment_hash: Optional[str] = None
    activated_by_owner: bool = False
    relays: List[str] = []


class Address(FromRowModel):
    id: str
    owner_id: Optional[str] = None
    domain_id: str
    local_part: str
    pubkey: str
    active: bool
    time: int
    reimburse_amount: int = 0
    # todo: expire

    config: AddressConfig = AddressConfig()

    @property
    def has_pubkey(self):
        return self.pubkey != ""

    @classmethod
    def from_row(cls, row: Row) -> "Address":
        address = cls(**dict(row))
        if row["extra"]:
            address.config = AddressConfig(**json.loads(row["extra"]))
        return address


class AddressStatus(BaseModel):
    identifier: str
    available: bool = False
    price: Optional[float] = None
    price_in_sats: Optional[float] = None
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
    reimburse_amount: str
    pubkey: str
    active: bool
    time: int


class Nip5Settings(BaseModel):
    cloudflare_access_token: Optional[str] = None

    @classmethod
    def from_row(cls, row: Row) -> "Nip5Settings":
        return cls(**dict(json.loads(row["settings"])))
