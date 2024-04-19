def get_blank_id(total_closed_options):
    return total_closed_options

def get_null_id(total_closed_options):
    return total_closed_options + 1

def get_blank_ballot(total_closed_options, len_ballot):
    blank_id = get_blank_id(total_closed_options)
    return [blank_id]*len_ballot

def get_null_ballot(total_closed_options, len_ballot):
    null_id = get_null_id(total_closed_options)
    return [null_id]*len_ballot

def is_blank_ballot(ballot, total_closed_options, max_len_ballot):
    return ballot == get_blank_ballot(total_closed_options, max_len_ballot)

def is_null_ballot(ballot, total_closed_options, max_len_ballot):
    return ballot == get_null_ballot(total_closed_options, max_len_ballot)

def is_invalid_ballot(
    ballot, total_closed_options, total_formal_options, max_len_ballot,
):  
    if len(ballot) > max_len_ballot:
        return True

    blank_id = get_blank_id(total_closed_options)
    for candidate in ballot:
        is_formal = (
            candidate in list(range(total_formal_options))
            and ballot.count(candidate) == 1
        )
        is_blank = candidate == blank_id
        is_valid = is_formal or is_blank
        if not is_valid:
            return True
    return False

## -----------------------------------------
## STV
def parseRoundResumes(round_resumes):
	resumes = []
	for resume in round_resumes:
		resumes.append([
            resume['elected'], resume['rejected'], resume['hopeful']
        ])
	return resumes

def parseTalliesResumes(tallies_resumes):
	resumes = []
	for resume in tallies_resumes:
		new_resume = []
		for clave, valor in resume.items():
			new_resume.append([clave, valor])
		resumes.append(new_resume)
	return resumes
