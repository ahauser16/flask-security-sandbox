
last commit includes broken code related to the error below:

Google Cloud Services is too complicated to set up at this time but the `/mydocuments` route I was working with is below followed by the error.

```
@app.route("/mydocuments", methods=["GET", "POST"])
@roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
def mydocuments():
    form = UploadDocumentForm()
    if form.validate_on_submit():
        f = form.document.data
        filename = secure_filename(f.filename)

        # Create a Cloud Storage client.
        gcs = storage.Client.from_service_account_json(
            app.config["GOOGLE_APPLICATION_CREDENTIALS"]
        )

        # Get the bucket that the file will be uploaded to.
        bucket = gcs.get_bucket(current_app.config["NOTARIOUS_TEST_BUCKET"])

        # Create a new blob and upload the file's content.
        blob = bucket.blob(filename)
        blob.upload_from_string(f.read(), content_type=f.content_type)

        # Make the blob publicly viewable.
        blob.make_public()

        # The URL can be used to directly access the uploaded file.
        file_url = blob.public_url
        # Create a new PDFDocument object
        document = PDFDocument(
            filename=filename,
            file_url=file_url,
            user_id=current_user.id,
            size=blob.size,
            content_type=f.content_type,
        )

        # Get the document role
        document_role_name = form.document_role.data
        document_role = DocumentRole.query.filter_by(name=document_role_name).first()

        # Add the document role to the document
        document.document_roles.append(document_role)

        # Add the document to the session and commit
        db.session.add(document)
        db.session.commit()

        return redirect(url_for("mydocuments"))
    return render_template("mydocuments.html", form=form)
```

error:

```
127.0.0.1 - - [04/Jun/2024 19:24:23] "POST /mydocuments HTTP/1.1" 500 -
Traceback (most recent call last):
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/flask/app.py", line 2552, in __call__
    return self.wsgi_app(environ, start_response)
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/flask/app.py", line 2532, in wsgi_app
    response = self.handle_exception(e)
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/flask/app.py", line 2529, in wsgi_app
    response = self.full_dispatch_request()
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/flask/app.py", line 1825, in full_dispatch_request
    rv = self.handle_user_exception(e)
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/flask/app.py", line 1823, in full_dispatch_request
    rv = self.dispatch_request()
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/flask/app.py", line 1799, in dispatch_request
    return self.ensure_sync(self.view_functions[rule.endpoint])(**view_args)
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/flask_security/decorators.py", line 216, in decorated_view
    return fn(*args, **kwargs)
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/app.py", line 695, in mydocuments
    bucket = gcs.get_bucket(current_app.config["NOTARIOUS_TEST_BUCKET"])
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/google/cloud/storage/client.py", line 857, in get_bucket
    bucket.reload(
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/google/cloud/storage/bucket.py", line 1083, in reload
    super(Bucket, self).reload(
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/google/cloud/storage/_helpers.py", line 300, in reload
    api_response = client._get_resource(
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/google/cloud/storage/client.py", line 462, in _get_resource
    return self._connection.api_request(
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/google/cloud/storage/_http.py", line 78, in api_request
    return call()
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/google/api_core/retry/retry_unary.py", line 293, in retry_wrapped_func
    return retry_target(
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/google/api_core/retry/retry_unary.py", line 153, in retry_target
    _retry_error_helper(
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/google/api_core/retry/retry_base.py", line 212, in _retry_error_helper
    raise final_exc from source_exc
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/google/api_core/retry/retry_unary.py", line 144, in retry_target
    result = target()
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/google/cloud/_http/__init__.py", line 482, in api_request
    response = self._make_request(
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/google/cloud/_http/__init__.py", line 341, in _make_request
    return self._do_request(
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/google/cloud/_http/__init__.py", line 379, in _do_request
    return self.http.request(
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/google/auth/transport/requests.py", line 537, in request
    self.credentials.before_request(auth_request, method, url, request_headers)
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/google/auth/credentials.py", line 230, in before_request
    self._blocking_refresh(request)
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/google/auth/credentials.py", line 193, in _blocking_refresh
    self.refresh(request)
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/google/oauth2/service_account.py", line 445, in refresh
    access_token, expiry, _ = _client.jwt_grant(
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/google/oauth2/_client.py", line 308, in jwt_grant
    response_data = _token_endpoint_request(
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/google/oauth2/_client.py", line 279, in _token_endpoint_request
    _handle_error_response(response_data, retryable_error)
  File "/home/haus/springboard_bootcamp_dec_2023/flask-rbac-tutorial/venv/lib/python3.10/site-packages/google/oauth2/_client.py", line 72, in _handle_error_response
    raise exceptions.RefreshError(
google.auth.exceptions.RefreshError: ('invalid_grant: Invalid JWT: Token must be a short-lived token (60 minutes) and in a reasonable timeframe. Check your iat and exp values in the JWT claim.', {'error': 'invalid_grant', 'error_description': 'Invalid JWT: Token must be a short-lived token (60 minutes) and in a reasonable timeframe. Check your iat and exp values in the JWT claim.'})
```

Start next session to debug using the following instructions:

The error message indicates that the JWT (JSON Web Token) used for authentication with Google Cloud Storage is invalid. The error message suggests that the token must be a short-lived token (60 minutes) and in a reasonable timeframe.

This error can occur if the system clock on your machine is not synchronized with the correct time. The JWT includes an issued at time (iat) and an expiration time (exp), and if your system clock is too far ahead or behind, the token may be considered invalid.

Here are a few steps to fix this issue:

1. Check your system clock and ensure it's correct. If it's not, correct it.

2. If you're using a service account for authentication, make sure the service account has the necessary permissions to access the bucket.

3. If you're generating the JWT yourself, ensure that the iat (issued at) and exp (expiration) claims are set correctly. The exp claim should be a timestamp in the future, but not more than 60 minutes from the iat claim.

4. If you're using a library to authenticate, it may be handling the JWT generation for you. In this case, updating the library to the latest version may help.

5. If none of the above steps work, you may need to create a new service account and use it for authentication.

### debug notes continued 6/7//24:

```
The error message indicates that the JWT token used for authentication is invalid because it's not a short-lived token (60 minutes) and/or it's not in a reasonable timeframe. This could be due to the iat (issued at) and exp (expiration) values in the JWT claim.

Given that you've already checked your system clock and it's correct, the issue might be with how the JWT token is being generated or used in your application. Here are a few things you can check:

1. Token Generation: Ensure that the JWT token is being generated correctly, with the iat set to the current time and the exp set to 60 minutes from the current time.

2. Token Usage: Ensure that the token is being used immediately after being generated and not being stored or reused. JWT tokens are meant to be used once and then discarded.

3. Service Account Key: Ensure that the service account key file used to authenticate your application is correct and up-to-date. If you're not sure, you can create a new service account key file in the Google Cloud Console and update your application to use the new key file.

4. Library Versions: Ensure that you're using the latest versions of the Google Cloud client libraries. Sometimes, these kinds of issues can be caused by bugs in older versions of the libraries.

If none of these suggestions solve the issue, you might want to reach out to Google Cloud Support or the community support forums for more help.
```