import uuid

from fastapi import Depends, HTTPException, APIRouter
from sqlalchemy.orm import Session

from app.psifos.model import crud, schemas, models
from app.dependencies import get_db

from app.psifos_auth.model import models as auth_models
from app.psifos_auth.utils import token_required, election_route


api_router = APIRouter()

# ----- Election Admin Routes -----


@api_router.post("/create-election", status_code=201)
@token_required
def create_election(current_user: auth_models.User, election_in: schemas.ElectionIn, db: Session = Depends(get_db)):

    election_exists = crud.get_election_by_short_name(short_name=election_in.short_name) is not None
    if election_exists:
        raise HTTPException(status_code=404, detail="The election already exists.")

    uuid_election = str(uuid.uuid4())
    crud.create_election(db=db, election=election_in, admin_id=current_user.get_id(), uuid=uuid_election)
    return {"message": "Elección creada con exito!", "uuid": uuid_election}


@api_router.get("/get-election/{election_uuid}", response_model=schemas.ElectionOut, status_code=200)
@token_required
@election_route()
def get_election(election: models.Election, db: Session = Depends(get_db)):
    """
    Route for get a election by uuid
    """
    return election


@api_router.get("/get-election-stats/{election_uuid}", status_code=200)
@token_required
@election_route()
def get_election_stats(election: models.Election, db: Session = Depends(get_db)):
    """
    Route for get the stats of an election by uuid
    """
    return {
        "num_casted_votes": crud.get_num_casted_votes(
            db=db,
            election_id=election.id
        ),
        "total_voters": election.total_voters,
    }


@api_router.get("/get-elections", response_model=list[schemas.ElectionOut], status_code=200)
@token_required
def get_elections(current_user: models.User, db: Session = Depends(get_db)):
    """
    Route for get all elections
    """
    return [
        election for election 
        in crud.get_elections_by_user(
            db=db, 
            admin_id=current_user.get_id()
        )
    ]


@api_router.post("/edit-election/{election_uuid}", status_code=200)
@token_required
@election_route()
def edit_election(election: models.Election, electionIn: schemas.ElectionIn, db: Session = Depends(get_db)):
    """
    Route for edit a election
    Require a valid token to access >>> token_required
    """

    election_exist = crud.get_election_by_short_name(short_name=electionIn.short_name) is not None
    if election_exist:
        raise HTTPException(status_code=404, detail="The election already exists.")

    crud.edit_election(db=db, election_id=election.id, election=electionIn)
    return {"message": "Election edited successfully!"}
