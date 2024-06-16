from datetime import datetime
import pytz
from . import db

class NotarialAct(db.Model):
    __tablename__ = "notarial_act"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    date_time = db.Column(db.DateTime, default=datetime.utcnow)
    act_type = db.Column(db.String(100))
    principal_name = db.Column(db.String(100))
    principal_addressLine1 = db.Column(db.String(100))
    principal_addressLine2 = db.Column(db.String(100))
    principal_city = db.Column(db.String(100))
    principal_state = db.Column(db.String(2))
    principal_zipCode = db.Column(db.String(100))
    service_number = db.Column(db.Integer)
    service_type = db.Column(db.String(100))
    principal_credential_type = db.Column(db.String(100))
    communication_tech = db.Column(db.String(100), nullable=True)
    certification_authority = db.Column(db.String(100), nullable=True)
    verification_provider = db.Column(db.String(100), nullable=True)
    user = db.relationship("User", backref=db.backref("notarial_acts", lazy=True))

    def to_dict(self):
        if self.user and self.user.user_details and self.user.user_details.timezone:
            user_tz = pytz.timezone(self.user.user_details.timezone)
            local_date_time = (
                self.date_time.astimezone(user_tz) if self.date_time else None
            )
        else:
            local_date_time = self.date_time

        return {
            "id": self.id,
            "user_id": self.user_id,
            "date_time": (
                local_date_time.strftime("%Y-%m-%d %H:%M:%S")
                if local_date_time
                else None
            ),
            "act_type": self.act_type,
            "principal_name": self.principal_name,
            "principal_addressLine1": self.principal_addressLine1,
            "principal_addressLine2": self.principal_addressLine2,
            "principal_city": self.principal_city,
            "principal_state": self.principal_state,
            "principal_zipCode": self.principal_zipCode,
            "service_number": self.service_number,
            "service_type": self.service_type,
            "principal_credential_type": self.principal_credential_type,
            "communication_tech": self.communication_tech,
            "certification_authority": self.certification_authority,
            "verification_provider": self.verification_provider,
        }