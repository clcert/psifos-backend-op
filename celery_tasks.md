# Celery Tasks

- Verify castvote & store
- Compute tally
- Psifos decrypt
- Process VoterFile

```python
# VOTERFILE HELIOS

class VoterFile(models.Model):
  """
  A model to store files that are lists of voters to be processed
  """
  # path where we store voter upload
  PATH = settings.VOTER_UPLOAD_REL_PATH

  election = models.ForeignKey(Election, on_delete=models.CASCADE)

  # we move to storing the content in the DB
  voter_file = models.FileField(upload_to=PATH, max_length=250,null=True)
  voter_file_content = models.TextField(null=True)

  uploaded_at = models.DateTimeField(auto_now_add=True)
  processing_started_at = models.DateTimeField(auto_now_add=False, null=True)
  processing_finished_at = models.DateTimeField(auto_now_add=False, null=True)
  num_voters = models.IntegerField(null=True)

  class Meta:
    app_label = 'helios'

  def itervoters(self):
    if self.voter_file_content:
      if isinstance(self.voter_file_content, str):
        content = self.voter_file_content.encode(encoding='utf-8')
      elif isinstance(self.voter_file_content, bytes):
        content = self.voter_file_content
      else:
        raise TypeError("voter_file_content is of type {0} instead of str or bytes"
                        .format(str(type(self.voter_file_content))))

      # now we have to handle non-universal-newline stuff
      # we do this in a simple way: replace all \r with \n
      # then, replace all double \n with single \n
      # this should leave us with only \n
      content = content.replace(b'\r',b'\n').replace(b'\n\n',b'\n')

      close = False
      voter_stream = io.BytesIO(content)
    else:
      close = True
      voter_stream = open(self.voter_file.path, "rb")

    #reader = unicode_csv_reader(voter_stream)
    reader = unicodecsv.reader(voter_stream, encoding='utf-8')

    for voter_fields in reader:
      # bad line
      if len(voter_fields) < 1:
        continue

      return_dict = {'voter_id': voter_fields[0].strip()}

      if len(voter_fields) > 1:
        return_dict['email'] = voter_fields[1].strip()
      else:
        # assume single field means the email is the same field
        return_dict['email'] = voter_fields[0].strip()

      if len(voter_fields) > 2:
        return_dict['name'] = voter_fields[2].strip()
      else:
        return_dict['name'] = return_dict['email']

      if len(voter_fields) > 3:
        return_dict['voter_weight'] = voter_fields[3].strip()
      else:
        return_dict['voter_weight'] = return_dict['voter_weight']

      yield return_dict
    if close:
      voter_stream.close()

  def process(self):
    self.processing_started_at = datetime.datetime.utcnow()
    self.save()

    election = self.election
    last_alias_num = election.last_alias_num

    num_voters = 0
    new_voters = []
    for voter in self.itervoters():
      num_voters += 1

      # does voter for this user already exist
      existing_voter = Voter.get_by_election_and_voter_id(election, voter['voter_id'])

      # create auth user
      # cas_auth_user = User.update_or_create(user_type='cas', name=voter['name'], user_id=voter['voter_id'], info={'name':voter['name']})
      # cas_auth_user.save()
      # cas_created_user = User.get_by_type_and_id(user_type='cas', user_id=voter['voter_id'])
      oauth_auth_user = User.update_or_create(user_type='oauth2', name=voter['name'], user_id=voter['voter_id'], info={'name':voter['name']})
      oauth_auth_user.save()
      oauth_created_user = User.get_by_type_and_id(user_type='oauth2', user_id=voter['voter_id'])

      # create the voter
      if not existing_voter:
        voter_uuid = str(uuid.uuid4())
        existing_voter = Voter(uuid= voter_uuid, user = None, voter_login_id = voter['voter_id'],
                      voter_name = voter['name'], voter_email = voter['email'], election = election, user_id=oauth_created_user.id,
                               voter_weight=voter['voter_weight'])
        # existing_voter.generate_password()
        new_voters.append(existing_voter)
        existing_voter.save()

    if election.use_voter_aliases:
      voter_alias_integers = list(range(last_alias_num+1, last_alias_num+1+num_voters))
      random.shuffle(voter_alias_integers)
      for i, voter in enumerate(new_voters):
        voter.alias = 'V%s' % voter_alias_integers[i]
        voter.save()

    self.num_voters = num_voters
    self.processing_finished_at = datetime.datetime.utcnow()
    self.save()

    return num_voters
```