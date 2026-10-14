"""Claim Check - Lost and Found System (Flask + OOP, list-based storage)."""
import os
import uuid
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from functools import wraps

from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")
DEFAULT_LOST_IMAGE = "/static/images/lost-item-default.svg"
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads", "lost")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

CATEGORIES = ["Electronics", "Bags", "Clothing", "Keys", "Books & Stationery",
              "Water Bottles & Lunchboxes", "ID & Cards", "Money", "Other"]


# --------------------------------------------------------------------------
# Custom exceptions
# --------------------------------------------------------------------------
class LostFoundError(Exception):
    """Base class for expected, user-facing errors."""


class DuplicateError(LostFoundError):
    pass


class NotFoundError(LostFoundError):
    pass


class InvalidOperationError(LostFoundError):
    pass


# --------------------------------------------------------------------------
# OOP model
# --------------------------------------------------------------------------
class Record:
    """Parent class for everything stored in the system's lists."""

    def __init__(self, record_id):
        self._id = record_id

    @property
    def id(self):
        return self._id

    def summary(self):  # overridden by child classes (polymorphism)
        return f"Record #{self._id}"


class User(Record):
    """Parent of all account types. Username and password hash are private."""

    role = "user"
    role_label = "User"
    home_endpoint = "dashboard"

    def __init__(self, uid, username, password, full_name):
        super().__init__(uid)
        self.__username = username.strip().lower()
        self.__password_hash = generate_password_hash(password)
        self.full_name = full_name.strip()
        self._is_active = True

    @property
    def is_active(self):
        return self._is_active

    def activate(self):
        self._is_active = True

    def deactivate(self):
        self._is_active = False

    @property
    def username(self):
        return self.__username

    def check_password(self, password):
        return check_password_hash(self.__password_hash, password)

    def set_password(self, password):
        self.__password_hash = generate_password_hash(password)

    def copy_credentials_from(self, other):
        self.__password_hash = other._User__password_hash

    def permissions(self):
        return set()

    def can(self, permission):
        return permission in self.permissions()

    def summary(self):
        return f"{self.role_label}: {self.full_name} ({self.username})"


class Administrator(User):
    role = "admin"
    role_label = "Administrator"
    home_endpoint = "admin_dashboard"

    def permissions(self):  # overrides User.permissions
        return {"items.add", "items.edit", "items.delete", "items.search",
                "items.view_all", "users.manage", "claims.view_all",
                "claims.process", "claims.delete"}


class Staff(User):
    role = "staff"
    role_label = "Lost & Found Officer"
    home_endpoint = "staff_dashboard"

    def permissions(self):
        return {"items.add", "items.edit", "items.search", "items.view_all",
                "claims.view_all", "claims.process"}


class Student(User):
    role = "student"
    role_label = "Student"
    home_endpoint = "student_dashboard"

    def permissions(self):
        return {"items.search", "lost.report", "claims.submit"}


USER_CLASSES = {"admin": Administrator, "staff": Staff, "student": Student}


class Item(Record):
    """Parent of FoundItem and LostReport. Stored together in one list."""

    kind = "item"
    kind_label = "Item"
    statuses = ()

    def __init__(self, item_id, name, category, description, location, when, owner_id, amount=None):
        super().__init__(item_id)
        self.name = name
        self.category = category
        self.description = description
        self.location = location
        self.when = when
        self.owner_id = owner_id          # who recorded it
        self.amount = amount
        self.image_url = None
        self._status = self.statuses[0]
        self.created = datetime.now()

    @property
    def status(self):
        return self._status

    def set_status(self, status):
        if status not in self.statuses:
            raise InvalidOperationError("That status isn't valid for this record.")
        self._status = status

    @property
    def is_active(self):
        return self._status == self.statuses[0]

    def can_edit(self, user):
        return user.can("items.edit")

    def can_delete(self, user):
        return user.can("items.delete")

    def summary(self):
        return f'{self.kind_label}: "{self.name}"'


class FoundItem(Item):
    """An item handed in to the office. The identifying detail is private
    so it can be used to verify a claim but never shown to claimants."""

    kind = "found"
    kind_label = "Found item"
    statuses = ("in storage", "returned", "donated")

    def __init__(self, item_id, name, category, description, location, when,
                 owner_id, identifier, amount=None):
        super().__init__(item_id, name, category, description, location, when, owner_id, amount)
        self.__identifier = identifier
        self.returned_to = None

    @property
    def identifier(self):
        """Hidden verification detail; templates only show it to staff/admin."""
        return self.__identifier

    def set_identifier(self, text):
        self.__identifier = text

    def return_to(self, student_id):
        if not self.is_active:
            raise InvalidOperationError("This item is no longer in storage.")
        self._status = "returned"
        self.returned_to = student_id


class LostReport(Item):
    """A student's report of something they lost."""

    kind = "lost"
    kind_label = "Lost report"
    statuses = ("open", "resolved")

    def __init__(self, item_id, name, category, description, location, when, owner_id,
                 image_url=None, amount=None):
        super().__init__(item_id, name, category, description, location, when, owner_id, amount)
        self.image_url = image_url or DEFAULT_LOST_IMAGE

    def can_edit(self, user):  # overrides Item.can_edit
        return user.can("items.edit") or (
            user.can("lost.report") and self.owner_id == user.id and self.is_active)

    def can_delete(self, user):  # overrides Item.can_delete
        return user.can("items.delete") or (
            user.can("lost.report") and self.owner_id == user.id and self.is_active)


class Claim(Record):
    PENDING, APPROVED, REJECTED, CANCELLED = "pending", "approved", "rejected", "cancelled"

    def __init__(self, claim_id, item_id, student_id, proof):
        super().__init__(claim_id)
        self.item_id = item_id
        self.student_id = student_id
        self.proof = proof
        self.status = self.PENDING
        self.created = datetime.now()

    @property
    def is_open(self):
        return self.status == self.PENDING

    def summary(self):
        return f"Claim #{self.id} ({self.status})"


# --------------------------------------------------------------------------
# Temporary storage: plain Python lists (no database)
# --------------------------------------------------------------------------
USERS = []
ITEMS = []
CLAIMS = []
_counters = {"user": 0, "item": 0, "claim": 0}


def next_id(kind):
    _counters[kind] += 1
    return _counters[kind]


def find_user(uid):
    return next((u for u in USERS if u.id == uid), None)


def find_user_by_name(username):
    username = (username or "").strip().lower()
    return next((u for u in USERS if u.username == username), None)


def find_item(item_id):
    return next((i for i in ITEMS if i.id == item_id), None)


def get_item(item_id):
    item = find_item(item_id)
    if item is None:
        raise NotFoundError("That record no longer exists.")
    return item


def get_claim(claim_id):
    claim = next((c for c in CLAIMS if c.id == claim_id), None)
    if claim is None:
        raise NotFoundError("That claim no longer exists.")
    return claim


def get_user(uid):
    user = find_user(uid)
    if user is None:
        raise NotFoundError("That account no longer exists.")
    return user


def add_user(role, username, password, full_name):
    if find_user_by_name(username):
        raise DuplicateError(f'The username "{username.strip().lower()}" is already taken.')
    user = USER_CLASSES[role](next_id("user"), username, password, full_name)
    USERS.append(user)
    return user


def is_duplicate(kind, owner_id, name, location, when, ignore_id=None):
    return any(i.kind == kind and i.owner_id == owner_id and i.id != ignore_id
               and i.name.lower() == name.lower() and i.location.lower() == location.lower()
               and i.when == when for i in ITEMS)


def add_found(owner_id, name, category, description, location, when, identifier, amount=None):
    if is_duplicate("found", owner_id, name, location, when):
        raise DuplicateError("You already logged this item for the same place and date.")
    item = FoundItem(next_id("item"), name, category, description, location, when,
                     owner_id, identifier, amount)
    ITEMS.append(item)
    return item


def add_lost(owner_id, name, category, description, location, when, image_url=None, amount=None):
    if is_duplicate("lost", owner_id, name, location, when):
        raise DuplicateError("You already reported this item for the same place and date.")
    item = LostReport(next_id("item"), name, category, description, location, when,
                      owner_id, image_url, amount)
    ITEMS.append(item)
    return item


def save_lost_image(uploaded_file):
    if uploaded_file is None or not uploaded_file.filename:
        return DEFAULT_LOST_IMAGE

    filename = secure_filename(uploaded_file.filename)
    if not filename:
        return DEFAULT_LOST_IMAGE

    ext = os.path.splitext(filename)[1].lower()
    if ext not in {".png", ".jpg", ".jpeg", ".webp", ".gif"}:
        raise ValueError("Upload a JPG, PNG, GIF, or WebP image.")

    unique_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}{ext}"
    save_path = os.path.join(UPLOAD_FOLDER, unique_name)
    uploaded_file.save(save_path)
    return f"/static/uploads/lost/{unique_name}"


def seed():
    add_user("admin", "admin", "admin123", "Alex Reyes")
    add_user("staff", "staff", "staff123", "Sam Villanueva")
    add_user("student", "student", "student123", "Jamie Cruz")
    add_user("student", "maria", "maria123", "Maria Santos")
    today = date.today()
    for args in [
        ("Black umbrella", "Other", "Folding umbrella with a curved wooden handle.", "Library entrance", "Wooden handle has a red tape strip"),
        ("Blue water bottle", "Water Bottles & Lunchboxes", "Insulated 750 ml bottle, dented near the base.", "Gym bleachers", "Sticker of a cat on the bottom"),
        ("Scientific calculator", "Electronics", "Casio calculator in a grey slip case.", "Room 204", "Initials 'M.S.' written inside the battery cover"),
        ("House keys", "Keys", "Three keys on a green carabiner.", "Cafeteria", "Small brass bell on the ring"),
        ("Grey hoodie", "Clothing", "Size M zip-up hoodie.", "Auditorium row C", "Left cuff has a small ink stain"),
    ]:
        add_found(2, *args[:2], args[2], args[3], today, args[4])
    add_lost(3, "Black backpack", "Bags", "Nike backpack with a laptop sleeve and a keychain.", "Computer lab", today, "/static/images/lost-backpack.svg")
    add_lost(3, "Wired earbuds", "Electronics", "White earbuds in a small blue pouch.", "Room 110", today, "/static/images/lost-earbuds.svg")
    add_lost(4, "Math notebook", "Books & Stationery", "Green spiral notebook, name on the cover.", "Cafeteria", today, "/static/images/lost-notebook.svg")
    CLAIMS.append(Claim(next_id("claim"), 3, 4,
                        "It has my initials, M.S., written inside the battery cover."))


seed()


# --------------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------------
def current_user():
    uid = session.get("uid")
    if uid is None:
        return None
    user = find_user(uid)
    if user is None:
        session.clear()
    return user


def access(role=None, perm=None):
    """Restrict a route to a role and/or permission."""
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            user = current_user()
            if user is None:
                flash("Log in to continue.", "warning")
                return redirect(url_for("login"))
            if not user.is_active:
                session.clear()
                flash("This account has been deactivated. Contact the administrator.", "error")
                return redirect(url_for("login"))
            if (role and user.role != role) or (perm and not user.can(perm)):
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


@app.context_processor
def inject_globals():
    return {"current_user": current_user(), "categories": CATEGORIES,
            "today_iso": date.today().isoformat(),
            "name_of": lambda uid: (find_user(uid).full_name if find_user(uid) else "(deleted user)")}


# --------------------------------------------------------------------------
# Validation + view helpers
# --------------------------------------------------------------------------
def clean_item_form(form, needs_identifier):
    fields = ["name", "category", "description", "location", "date"]
    if needs_identifier:
        fields.append("identifier")
    data = {k: form.get(k, "").strip() for k in fields}
    labels = {"name": "item name", "category": "category", "description": "description",
              "location": "location", "date": "date", "identifier": "hidden identifying detail"}
    missing = [labels[k] for k, v in data.items() if not v]
    if missing:
        raise ValueError("Fill in every field: " + ", ".join(missing) + ".")
    if data["category"] not in CATEGORIES:
        raise ValueError("Choose a category from the list.")
    data["amount"] = None
    if data["category"] == "Money":
        amount_text = form.get("amount", "").strip()
        try:
            amount = Decimal(amount_text)
        except InvalidOperation:
            raise ValueError("Enter a valid amount for money items.")
        if not amount.is_finite() or amount <= 0:
            raise ValueError("Amount must be greater than zero.")
        data["amount"] = amount
    if len(data["name"]) > 80 or len(data["location"]) > 80:
        raise ValueError("Item name and location must be 80 characters or fewer.")
    if len(data["description"]) > 300 or len(data.get("identifier", "")) > 200:
        raise ValueError("Description must be 300 characters or fewer, and the hidden detail 200.")
    try:
        data["date"] = date.fromisoformat(data["date"])
    except ValueError:
        raise ValueError("Enter a valid date.")
    if data["date"] > date.today():
        raise ValueError("The date can't be in the future.")
    return data


def clean_user_form(form, password_required=True):
    data = {k: form.get(k, "").strip() for k in ("username", "full_name", "role")}
    data["password"] = form.get("password", "")
    if not data["username"] or not data["full_name"]:
        raise ValueError("Username and full name are required.")
    if not data["username"].replace("_", "").replace(".", "").isalnum():
        raise ValueError("Username may only contain letters, numbers, dots and underscores.")
    if data["role"] not in USER_CLASSES:
        raise ValueError("Choose a valid role.")
    if (password_required or data["password"]) and len(data["password"]) < 6:
        raise ValueError("Password must be at least 6 characters.")
    return data


def visible_items(user):
    """What each role is allowed to see (polymorphic by permission)."""
    if user.can("items.view_all"):
        return list(ITEMS)
    return [i for i in ITEMS if (i.kind == "found" and i.is_active)
            or (i.kind == "lost" and i.owner_id == user.id)]


def open_claim_item_ids(user):
    if user.can("claims.submit"):
        return {c.item_id for c in CLAIMS if c.student_id == user.id and c.is_open}
    return set()


def claim_rows(claims):
    rows = []
    for c in sorted(claims, key=lambda x: x.created, reverse=True):
        item, student = find_item(c.item_id), find_user(c.student_id)
        rows.append({"claim": c,
                     "item": item.name if item else "(deleted item)",
                     "identifier": item.identifier if isinstance(item, FoundItem) else "",
                     "student": student.full_name if student else "(deleted user)"})
    return rows


def newest(items):
    return sorted(items, key=lambda i: (i.when, i.created), reverse=True)


# --------------------------------------------------------------------------
# Routes: auth
# --------------------------------------------------------------------------
@app.route("/")
def index():
    user = current_user()
    return redirect(url_for(user.home_endpoint if user else "login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Enter both your username and password.", "error")
        else:
            user = find_user_by_name(username)
            if user and user.check_password(password):
                if not user.is_active:
                    flash("This account has been deactivated. Contact the administrator.", "error")
                    return render_template("login.html", signup_mode=False, form={})
                session.clear()
                session["uid"] = user.id
                flash(f"Welcome back, {user.full_name}.", "success")
                return redirect(url_for(user.home_endpoint))
            flash("Wrong username or password.", "error")
    return render_template("login.html", signup_mode=False, form={})


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user():
        return redirect(url_for("index"))
    form = {"role": "student"}
    if request.method == "POST":
        form = request.form
        try:
            d = clean_user_form(form)
            user = add_user(d["role"], d["username"], d["password"], d["full_name"])
            session.clear()
            session["uid"] = user.id
            flash(f"Account created. Welcome, {user.full_name}.", "success")
            return redirect(url_for(user.home_endpoint))
        except (ValueError, LostFoundError) as err:
            flash(str(err), "error")
    return render_template("login.html", signup_mode=True, form=form)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You're logged out.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@access()
def dashboard():
    return redirect(url_for(current_user().home_endpoint))


# --------------------------------------------------------------------------
# Routes: dashboards
# --------------------------------------------------------------------------
@app.route("/admin")
@access(role="admin")
def admin_dashboard():
    found = [i for i in ITEMS if i.kind == "found"]
    stats = {
        "stored": len([i for i in found if i.status == "in storage"]),
        "returned": len([i for i in found if i.status == "returned"]),
        "lost_open": len([i for i in ITEMS if i.kind == "lost" and i.is_active]),
        "pending": len([c for c in CLAIMS if c.is_open]),
        "accounts": len(USERS),
    }
    return render_template("dashboard_admin.html", stats=stats, rows=claim_rows(CLAIMS)[:6])


@app.route("/staff")
@access(role="staff")
def staff_dashboard():
    pending = [c for c in CLAIMS if c.is_open]
    open_lost = [i for i in ITEMS if i.kind == "lost" and i.is_active]
    stored = [i for i in ITEMS if i.kind == "found" and i.is_active]
    return render_template("dashboard_staff.html", pending=claim_rows(pending),
                           lost_count=len(open_lost), stored=newest(stored)[:5])


@app.route("/student")
@access(role="student")
def student_dashboard():
    me = current_user()
    mine_lost = [i for i in ITEMS if i.kind == "lost" and i.owner_id == me.id]
    my_claims = [c for c in CLAIMS if c.student_id == me.id]
    return render_template(
        "dashboard_student.html", lost=newest(mine_lost),
        claims=claim_rows(my_claims),
        browse_count=len([i for i in ITEMS if i.kind == "found" and i.is_active]))


# --------------------------------------------------------------------------
# Routes: items (CRUD) and search
# --------------------------------------------------------------------------
@app.route("/found")
@access()
def found_items():
    me = current_user()
    items = newest([i for i in visible_items(me) if i.kind == "found"])
    return render_template("found.html", items=items, claim_ids=open_claim_item_ids(me))


@app.route("/lost")
@access()
def lost_reports():
    me = current_user()
    if me.can("items.view_all"):
        items = [i for i in ITEMS if i.kind == "lost"]
    else:
        items = [i for i in ITEMS if i.kind == "lost" and i.owner_id == me.id]
    return render_template("lost.html", items=newest(items), claim_ids=set())


@app.route("/found/add", methods=["GET", "POST"])
@access(perm="items.add")
def found_add():
    form = {"date": date.today().isoformat()}
    if request.method == "POST":
        form = request.form
        try:
            d = clean_item_form(form, True)
            item = add_found(current_user().id, d["name"], d["category"], d["description"],
                             d["location"], d["date"], d["identifier"], d["amount"])
            flash(f"Logged {item.summary()}.", "success")
            return redirect(url_for("found_items"))
        except (ValueError, LostFoundError) as err:
            flash(str(err), "error")
    return render_template("item_form.html", form=form, item=None, kind="found")


@app.route("/lost/add", methods=["GET", "POST"])
@access(perm="lost.report")
def lost_add():
    form = {"date": date.today().isoformat()}
    if request.method == "POST":
        form = request.form
        try:
            d = clean_item_form(form, False)
            image_url = save_lost_image(request.files.get("image"))
            item = add_lost(current_user().id, d["name"], d["category"], d["description"],
                            d["location"], d["date"], image_url, d["amount"])
            flash(f"Reported {item.summary()}. Staff will watch for it.", "success")
            return redirect(url_for("lost_reports"))
        except (ValueError, LostFoundError) as err:
            flash(str(err), "error")
    return render_template("item_form.html", form=form, item=None, kind="lost")


@app.route("/items/<int:item_id>/edit", methods=["GET", "POST"])
@access()
def item_edit(item_id):
    me = current_user()
    try:
        item = get_item(item_id)
    except NotFoundError as err:
        flash(str(err), "error")
        return redirect(url_for("index"))
    if not item.can_edit(me):
        abort(403)
    form = {"name": item.name, "category": item.category, "description": item.description,
            "location": item.location, "date": item.when.isoformat(), "status": item.status,
            "identifier": item.identifier if item.kind == "found" else "",
            "amount": item.amount if item.amount is not None else ""}
    if request.method == "POST":
        form = request.form
        try:
            d = clean_item_form(form, item.kind == "found")
            if is_duplicate(item.kind, item.owner_id, d["name"], d["location"], d["date"], item.id):
                raise DuplicateError("Another record already has the same name, place and date.")
            status = form.get("status", item.status)
            if item.kind == "found" and item.status != status and status != "in storage" \
                    and any(c.item_id == item.id and c.is_open for c in CLAIMS):
                raise InvalidOperationError("Process the pending claims on this item first.")
            item.set_status(status)
            item.name, item.category, item.description = d["name"], d["category"], d["description"]
            item.location, item.when = d["location"], d["date"]
            item.amount = d["amount"]
            if item.kind == "lost":
                uploaded = request.files.get("image")
                if uploaded and uploaded.filename:
                    item.image_url = save_lost_image(uploaded)
            if item.kind == "found":
                item.set_identifier(d["identifier"])
            flash(f"Saved changes to {item.summary()}.", "success")
            return redirect(url_for("found_items" if item.kind == "found" else "lost_reports"))
        except (ValueError, LostFoundError) as err:
            flash(str(err), "error")
    return render_template("item_form.html", form=form, item=item, kind=item.kind)


@app.route("/items/<int:item_id>/delete", methods=["POST"])
@access()
def item_delete(item_id):
    me = current_user()
    try:
        item = get_item(item_id)
        if not item.can_delete(me):
            abort(403)
        if any(c.item_id == item.id and c.is_open for c in CLAIMS):
            raise InvalidOperationError("This item has pending claims. Process them first.")
        ITEMS.remove(item)
        flash(f"Deleted {item.summary()}.", "success")
        return redirect(url_for("found_items" if item.kind == "found" else "lost_reports"))
    except LostFoundError as err:
        flash(str(err), "error")
    return redirect(url_for("index"))


@app.route("/items/<int:item_id>/resolve", methods=["POST"])
@access()
def lost_resolve(item_id):
    try:
        item = get_item(item_id)
        if item.kind != "lost" or not item.can_edit(current_user()):
            abort(403)
        if not item.is_active:
            raise InvalidOperationError("This report is already resolved.")
        item.set_status("resolved")
        flash("Marked as found. Glad it turned up.", "success")
    except LostFoundError as err:
        flash(str(err), "error")
    return redirect(url_for("lost_reports"))


@app.route("/search")
@access(perm="items.search")
def search():
    me = current_user()
    q = request.args.get("q", "").strip().lower()
    category = request.args.get("category", "").strip()
    kind = request.args.get("kind", "")
    searched = bool(q or category or kind)
    results = []
    if searched:
        results = newest([i for i in visible_items(me)
                          if (not q or q in i.name.lower() or q in i.description.lower()
                              or q in i.location.lower())
                          and (not category or i.category == category)
                          and (not kind or i.kind == kind)])
    return render_template("search.html", items=results, searched=searched, q=request.args.get("q", ""),
                           category=category, kind=kind, claim_ids=open_claim_item_ids(me))


# --------------------------------------------------------------------------
# Routes: claims
# --------------------------------------------------------------------------
@app.route("/found/<int:item_id>/claim", methods=["GET", "POST"])
@access(perm="claims.submit")
def claim_item(item_id):
    me = current_user()
    try:
        item = get_item(item_id)
        if item.kind != "found" or not item.is_active:
            raise InvalidOperationError("This item can't be claimed.")
        if any(c.item_id == item_id and c.student_id == me.id and c.is_open for c in CLAIMS):
            raise DuplicateError("You already have a pending claim for this item.")
        if request.method == "POST":
            proof = request.form.get("proof", "").strip()
            if len(proof) < 10:
                flash("Describe something only the owner would know (at least 10 characters).", "error")
            elif len(proof) > 300:
                flash("Keep your description under 300 characters.", "error")
            else:
                CLAIMS.append(Claim(next_id("claim"), item_id, me.id, proof))
                flash("Claim sent. An officer will check it against the item.", "success")
                return redirect(url_for("my_claims"))
        return render_template("claim_form.html", item=item, proof=request.form.get("proof", ""))
    except LostFoundError as err:
        flash(str(err), "error")
        return redirect(url_for("found_items"))


@app.route("/my-claims")
@access(perm="claims.submit")
def my_claims():
    me = current_user()
    return render_template("my_claims.html",
                           rows=claim_rows([c for c in CLAIMS if c.student_id == me.id]))


@app.route("/claims/<int:claim_id>/cancel", methods=["POST"])
@access(perm="claims.submit")
def claim_cancel(claim_id):
    try:
        claim = get_claim(claim_id)
        if claim.student_id != current_user().id:
            abort(403)
        if not claim.is_open:
            raise InvalidOperationError("Only pending claims can be cancelled.")
        claim.status = Claim.CANCELLED
        flash("Claim cancelled.", "success")
    except LostFoundError as err:
        flash(str(err), "error")
    return redirect(url_for("my_claims"))


@app.route("/claims")
@access(perm="claims.view_all")
def claims_page():
    status = request.args.get("status", "")
    return render_template("claims.html", status=status,
                           rows=claim_rows([c for c in CLAIMS if not status or c.status == status]))


@app.route("/claims/<int:claim_id>/<action>", methods=["POST"])
@access(perm="claims.process")
def claim_action(claim_id, action):
    try:
        claim = get_claim(claim_id)
        item = find_item(claim.item_id)
        if action == "approve":
            if not claim.is_open:
                raise InvalidOperationError("Only pending claims can be approved.")
            if not isinstance(item, FoundItem):
                raise NotFoundError("The claimed item no longer exists.")
            item.return_to(claim.student_id)
            claim.status = Claim.APPROVED
            for other in CLAIMS:
                if other is not claim and other.item_id == item.id and other.is_open:
                    other.status = Claim.REJECTED
            flash("Approved. The item is marked as returned and other claims were closed.", "success")
        elif action == "reject":
            if not claim.is_open:
                raise InvalidOperationError("Only pending claims can be rejected.")
            claim.status = Claim.REJECTED
            flash("Claim rejected.", "success")
        elif action == "delete":
            if not current_user().can("claims.delete"):
                abort(403)
            CLAIMS.remove(claim)
            flash("Claim record deleted.", "success")
        else:
            raise InvalidOperationError("Unknown action.")
    except LostFoundError as err:
        flash(str(err), "error")
    return redirect(request.referrer or url_for("claims_page"))


# --------------------------------------------------------------------------
# Routes: user management (admin)
# --------------------------------------------------------------------------
@app.route("/users")
@access(perm="users.manage")
def users():
    return render_template("users.html", users=USERS)


@app.route("/users/add", methods=["GET", "POST"])
@access(perm="users.manage")
def user_add():
    form = {}
    if request.method == "POST":
        form = request.form
        try:
            d = clean_user_form(form)
            u = add_user(d["role"], d["username"], d["password"], d["full_name"])
            flash(f"Created {u.summary()}.", "success")
            return redirect(url_for("users"))
        except (ValueError, LostFoundError) as err:
            flash(str(err), "error")
    return render_template("user_form.html", form=form, target=None)


@app.route("/users/<int:uid>/edit", methods=["GET", "POST"])
@access(perm="users.manage")
def user_edit(uid):
    try:
        target = get_user(uid)
    except NotFoundError as err:
        flash(str(err), "error")
        return redirect(url_for("users"))
    form = {"username": target.username, "full_name": target.full_name, "role": target.role}
    if request.method == "POST":
        form = request.form
        try:
            d = clean_user_form(form, password_required=False)
            other = find_user_by_name(d["username"])
            if other and other.id != target.id:
                raise DuplicateError(f'The username "{d["username"].lower()}" is already taken.')
            if target.id == current_user().id and d["role"] != target.role:
                raise InvalidOperationError("You can't change your own role.")
            if d["role"] != target.role or d["username"].lower() != target.username:
                # Role and username are fixed per object, so rebuild it in the same slot.
                new = USER_CLASSES[d["role"]](target.id, d["username"],
                                              d["password"] or "temporary-pass", d["full_name"])
                if not d["password"]:
                    new.copy_credentials_from(target)
                USERS[USERS.index(target)] = new
            else:
                target.full_name = d["full_name"]
                if d["password"]:
                    target.set_password(d["password"])
            flash("Account updated.", "success")
            return redirect(url_for("users"))
        except (ValueError, LostFoundError) as err:
            flash(str(err), "error")
    return render_template("user_form.html", form=form, target=target)


@app.route("/users/<int:uid>/delete", methods=["POST"])
@access(perm="users.manage")
def user_delete(uid):
    try:
        target = get_user(uid)
        if target.id == current_user().id:
            raise InvalidOperationError("You can't delete your own account.")
        if any(c.student_id == uid and c.is_open for c in CLAIMS):
            raise InvalidOperationError("This member has pending claims. Process them first.")
        USERS.remove(target)
        flash(f"Deleted {target.summary()}.", "success")
    except LostFoundError as err:
        flash(str(err), "error")
    return redirect(url_for("users"))


@app.route("/users/<int:uid>/toggle-status", methods=["POST"])
@access(perm="users.manage")
def user_toggle_status(uid):
    try:
        target = get_user(uid)
        if target.id == current_user().id:
            raise InvalidOperationError("You can't deactivate your own account.")
        if target.is_active:
            target.deactivate()
            flash(f"Deactivated {target.full_name}'s account.", "success")
        else:
            target.activate()
            flash(f"Activated {target.full_name}'s account.", "success")
    except (LostFoundError, InvalidOperationError) as err:
        flash(str(err), "error")
    return redirect(url_for("users"))


# --------------------------------------------------------------------------
# Error pages
# --------------------------------------------------------------------------
@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, title="You can't open this page",
                           message="Your role doesn't have access to it."), 403


@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, title="Page not found",
                           message="The page you asked for doesn't exist."), 404


@app.errorhandler(405)
def not_allowed(_):
    return render_template("error.html", code=405, title="Action not allowed",
                           message="That action isn't available this way."), 405


@app.errorhandler(500)
def server_error(_):
    return render_template("error.html", code=500, title="Something went wrong",
                           message="The server hit an unexpected problem. Try again."), 500


if __name__ == "__main__":
    app.run(debug=True)
