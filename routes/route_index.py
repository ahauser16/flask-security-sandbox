from flask import render_template, redirect, url_for, request, jsonify, session, abort
from flask_security import utils, roles_accepted
from flask_login import login_user, current_user
from forms.signup_forms import (
    SignupForm,
    SignupPrincipalForm,
    SignupAdminForm,
    SignupNotaryForm,
    ConfirmRegistrationForm,
)
from models import User, Role, NotarialAct, roles_users
from flask_security import SQLAlchemySessionUserDatastore


def add_routes_to_app(app):
    @app.route("/")
    def index():
        return render_template("base.html")

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        form = SignupForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                return render_template(
                    "signup.html", form=form, msg="User already exist"
                )

            role = Role.query.filter_by(id=form.options.data).first()
            session["email"] = form.email.data
            session["password"] = form.password.data
            session["role_id"] = role.id

            if role.name == "Admin":
                return redirect(url_for("signup_admin"))
            elif role.name == "Principal":
                return redirect(url_for("signup_principal"))
            elif role.name in ["Traditional Notary", "Electronic Notary"]:
                return redirect(url_for("signup_notary"))
        return render_template("signup.html", form=form)

    @app.route("/signup_admin", methods=["GET", "POST"])
    def signup_admin():
        form = SignupAdminForm()

        if form.validate_on_submit():
            return redirect(url_for("confirm_registration"))

        # Set the default value for the email field here, inside the route function
        form.email.data = session.get("email")
        form.password.data = session.get("password")

        return render_template("signup_admin.html", form=form)

    @app.route("/signup_principal", methods=["GET", "POST"])
    def signup_principal():
        form = SignupPrincipalForm()

        if form.validate_on_submit():
            return redirect(url_for("confirm_registration"))

        # Set the default value for the email field here, inside the route function
        form.email.data = session.get("email")
        form.password.data = session.get("password")

        return render_template("signup_principal.html", form=form)

    @app.route("/signup_notary", methods=["GET", "POST"])
    def signup_notary():
        form = SignupNotaryForm()

        if form.validate_on_submit():
            return redirect(url_for("confirm_registration"))

        # Set the default value for the email and password fields here, inside the route function
        form.email.data = session.get("email")
        form.password.data = session.get("password")

        return render_template("signup_notary.html", form=form)

    @app.route("/confirm_registration", methods=["GET", "POST"])
    def confirm_registration():
        form = ConfirmRegistrationForm()
        if form.validate_on_submit():
            user = user_datastore.create_user(
                email=session["email"], password=session["password"]
            )
            role = Role.query.filter_by(id=session["role_id"]).first()
            user_datastore.add_role_to_user(user, role)
            db.session.commit()
            login_user(user)
            return redirect(url_for("index"))
        else:
            return render_template("signup_final.html", form=form, session=session)

    @app.route("/signin", methods=["GET", "POST"])
    def signin():
        msg = ""
        if request.method == "POST":
            user = User.query.filter_by(email=request.form["email"]).first()
            if user:
                if utils.verify_and_update_password(request.form["password"], user):
                    login_user(user)
                    return redirect(url_for("index"))
                else:
                    msg = "Wrong password"
            else:
                msg = "User doesn't exist"
            return render_template("signin.html", msg=msg)
        else:
            return render_template("signin.html", msg=msg)

    @app.route("/api/notarial_act_data")
    def notarial_act_data():
        query = NotarialAct.query.filter_by(user_id=current_user.id)

        # search filter
        search = request.args.get("search")
        if search:
            query = query.filter(NotarialAct.act_type.like(f"%{search}%"))

        total = query.count()

        # sorting
        sort = request.args.get("sort")
        if sort:
            order = []
            for s in sort.split(","):
                direction = s[0]
                name = s[1:]
                if name not in ["date", "time", "act_type"]:
                    name = "date"
                col = getattr(NotarialAct, name)
                if direction == "-":
                    col = col.desc()
                order.append(col)
            if order:
                query = query.order_by(*order)

        # pagination
        start = request.args.get("start", type=int, default=-1)
        length = request.args.get("length", type=int, default=-1)
        if start != -1 and length != -1:
            query = query.offset(start).limit(length)

        # response
        return {
            "data": [act.to_dict() for act in query],
            "total": total,
        }

    @app.route("/api/notarial_act_data", methods=["POST"])
    def update_notarial_act():
        data = request.get_json()
        if "id" not in data:
            abort(400)
        act = NotarialAct.query.get(data["id"])
        for field in ["date", "time", "act_type"]:
            if field in data:
                setattr(act, field, data[field])
        db.session.commit()
        return "", 204

    @app.route("/principals")
    @roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
    def principals():
        principals = ["johndoe@abc.com", "sumguy@abc.com", "princ5000@abc.com"]
        role_principals = db.session.query(roles_users).filter_by(role_id=2)
        for principal in role_principals:
            user = User.query.filter_by(id=principal.user_id).first()
            principals.append(user.email)
        return render_template("principals.html", principals=principals)

    @app.route("/trad_notaries")
    @roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
    def trad_notaries():
        trad_notaries = ["oldmannotary@aol.com", "papyrus@friendster.com"]
        role_trad_notaries = db.session.query(roles_users).filter_by(role_id=3)
        for trad_notary in role_trad_notaries:
            user = User.query.filter_by(id=trad_notary.user_id).first()
            trad_notaries.append(user.email)
        return render_template("traditionalnotaries.html", trad_notaries=trad_notaries)

    @app.route("/e_notaries")
    @roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
    def e_notaries():
        e_notaries = ["amazo@gmail.com", "thefuture@yahoo.com"]
        role_e_notaries = db.session.query(roles_users).filter_by(role_id=4)
        for e_notary in role_e_notaries:
            user = User.query.filter_by(id=e_notary.user_id).first()
            e_notaries.append(user.email)
        return render_template("electronicnotaries.html", e_notaries=e_notaries)

    @app.route("/mydetails")
    @roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
    def mydetails():
        return render_template("mydetails.html")

    @app.route("/notarylogbook")
    @roles_accepted("Admin", "Traditional Notary", "Electronic Notary")
    def notarylogbook():
        return render_template(
            "mynotarylogbook.html", notarial_acts=current_user.notarial_acts
        )

    @app.route("/addnotarylogentry", methods=["GET", "POST"])
    def add_notary_log_entry():
        if request.method == "POST":
            act = NotarialAct(
                date=request.form.get("date"),
                time=request.form.get("time"),
                act_type=request.form.get("act_type"),
                other_act_type_input=request.form.get("other_act_type_input"),
                principal_name=request.form.get("principal_name"),
                principal_addressLine1=request.form.get("principal_addressLine1"),
                principal_addressLine2=request.form.get("principal_addressLine2"),
                principal_city=request.form.get("principal_city"),
                principal_state=request.form.get("principal_state"),
                principal_zipCode=request.form.get("principal_zipCode"),
                service_number=request.form.get("service_number"),
                service_type=request.form.get("service_type"),
                credential_type=request.form.get("credential_type"),
                communication_tech=request.form.get("communication_tech"),
                certification_authority=request.form.get("certification_authority"),
                verification_provider=request.form.get("verification_provider"),
            )
            db.session.add(act)
            db.session.commit()
        return render_template("addnotarialactform.html")

    @app.route("/findnotary")
    # @roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
    def findnotary():
        return render_template("findnotary.html")

    @app.route("/myesignature")
    @roles_accepted("Admin", "Principal", "Traditional Notary", "Electronic Notary")
    def myesignature():
        return render_template("myesignature.html")
