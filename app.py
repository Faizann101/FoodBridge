import os
import math
from datetime import datetime
from decimal import Decimal, InvalidOperation
from functools import wraps

import pymysql
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-this-before-deployment")


def get_db():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT", 4000)),
        user=os.getenv("DB_USERNAME"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_DATABASE", "foodbridge"),
        ssl={"ca": os.getenv("DB_SSL_CA", "certs/ca.pem")},
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
        connect_timeout=15,
    )


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped_view


def role_required(role):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped_view(*args, **kwargs):
            if session.get("role") != role:
                flash("You do not have permission to access that page.", "danger")
                return redirect(url_for("index"))
            return view(*args, **kwargs)
        return wrapped_view
    return decorator


def close_connection(connection):
    if connection:
        connection.close()


@app.context_processor
def inject_pending_request_count():
    """Expose the donor's global pending-request count to the navigation."""
    if session.get("role") != "donor" or not session.get("user_id"):
        return {"pending_request_count": 0}

    connection = None
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*) AS pending_count
                FROM food_requests r
                JOIN food_listings f ON f.listing_id = r.listing_id
                WHERE f.donor_id = %s AND r.status = 'pending'
                """,
                (session["user_id"],),
            )
            row = cursor.fetchone()
            return {"pending_request_count": int(row["pending_count"] if row else 0)}
    except Exception:
        # Do not break page rendering if the count cannot be retrieved.
        return {"pending_request_count": 0}
    finally:
        close_connection(connection)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    connection = None
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute("SELECT DATABASE() AS database_name")
            result = cursor.fetchone()
        return {"status": "ok", "database": result["database_name"]}
    except Exception:
        app.logger.exception("Database health check failed")
        return {"status": "error", "message": "Database connection failed"}, 500
    finally:
        close_connection(connection)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "")
        organization_name = request.form.get("organization_name", "").strip() or None
        phone = request.form.get("phone", "").strip() or None
        country = request.form.get("country", "").strip()
        city = request.form.get("city", "").strip()
        locality = request.form.get("locality", "").strip() or None

        if not all([full_name, email, password, country, city]):
            flash("Please fill in all required fields.", "danger")
            return render_template("register.html")
        if role not in ("donor", "recipient"):
            flash("Please select a valid account type.", "danger")
            return render_template("register.html")
        if len(password) < 8:
            flash("Your password must contain at least 8 characters.", "danger")
            return render_template("register.html")

        connection = None
        try:
            connection = get_db()
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO users
                        (full_name, email, password_hash, role, organization_name,
                         phone, country, city, locality)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        full_name, email, generate_password_hash(password), role,
                        organization_name, phone, country, city, locality
                    ),
                )
            connection.commit()
            flash("Account created. You can now log in.", "success")
            return redirect(url_for("login"))
        except pymysql.err.IntegrityError:
            if connection:
                connection.rollback()
            flash("An account with that email already exists.", "danger")
        except Exception:
            if connection:
                connection.rollback()
            app.logger.exception("Registration failed")
            flash("Registration failed. Please try again.", "danger")
        finally:
            close_connection(connection)

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        connection = None
        try:
            connection = get_db()
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT user_id, full_name, email, password_hash, role
                    FROM users WHERE email = %s
                    """,
                    (email,),
                )
                user = cursor.fetchone()
        except Exception:
            app.logger.exception("Login database query failed")
            flash("Login is temporarily unavailable. Please try again.", "danger")
            user = None
        finally:
            close_connection(connection)

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["user_id"]
            session["full_name"] = user["full_name"]
            session["role"] = user["role"]
            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "danger")
    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    if session.get("role") == "donor":
        return redirect(url_for("donor_dashboard"))
    return redirect(url_for("recipient_dashboard"))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


@app.route("/profile")
@login_required
def profile():
    connection = None
    user = None
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT user_id, full_name, email, role, organization_name,
                       phone, country, city, locality, created_at
                FROM users
                WHERE user_id = %s
                """,
                (session["user_id"],),
            )
            user = cursor.fetchone()
    except Exception:
        app.logger.exception("Loading profile failed")
        flash("Could not load your profile. Please try again.", "danger")
        return redirect(url_for("dashboard"))
    finally:
        close_connection(connection)

    if not user:
        session.clear()
        flash("Your account could not be found. Please log in again.", "warning")
        return redirect(url_for("login"))

    return render_template("profile.html", user=user)


@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    connection = None
    user = None

    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT user_id, full_name, email, role, organization_name,
                       phone, country, city, locality, created_at
                FROM users
                WHERE user_id = %s
                """,
                (session["user_id"],),
            )
            user = cursor.fetchone()
    except Exception:
        app.logger.exception("Loading profile for editing failed")
        flash("Could not load your profile. Please try again.", "danger")
        return redirect(url_for("dashboard"))
    finally:
        close_connection(connection)

    if not user:
        session.clear()
        flash("Your account could not be found. Please log in again.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        organization_name = request.form.get("organization_name", "").strip() or None
        phone = request.form.get("phone", "").strip() or None
        country = request.form.get("country", "").strip()
        city = request.form.get("city", "").strip()
        locality = request.form.get("locality", "").strip() or None

        if not full_name or not country or not city:
            flash("Name, country, and city are required.", "danger")
            user.update({
                "full_name": full_name,
                "organization_name": organization_name,
                "phone": phone,
                "country": country,
                "city": city,
                "locality": locality,
            })
            return render_template("edit_profile.html", user=user)

        connection = None
        try:
            connection = get_db()
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE users
                    SET full_name = %s, organization_name = %s, phone = %s,
                        country = %s, city = %s, locality = %s
                    WHERE user_id = %s
                    """,
                    (
                        full_name, organization_name, phone, country, city,
                        locality, session["user_id"],
                    ),
                )
            connection.commit()
            session["full_name"] = full_name
            flash("Your profile has been updated.", "success")
            return redirect(url_for("profile"))
        except Exception:
            if connection:
                connection.rollback()
            app.logger.exception("Updating profile failed")
            flash("Could not save your changes. Please try again.", "danger")
        finally:
            close_connection(connection)

        user.update({
            "full_name": full_name,
            "organization_name": organization_name,
            "phone": phone,
            "country": country,
            "city": city,
            "locality": locality,
        })

    return render_template("edit_profile.html", user=user)


@app.route("/donor")
@role_required("donor")
def donor_dashboard():
    connection = None
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT f.*,
                       (SELECT COUNT(*) FROM food_requests r
                        WHERE r.listing_id = f.listing_id AND r.status = 'pending')
                       AS pending_request_count
                FROM food_listings f
                WHERE f.donor_id = %s
                  AND f.pickup_deadline > NOW()
                  AND f.status IN ('available', 'reserved')
                ORDER BY f.created_at DESC
                """,
                (session["user_id"],),
            )
            listings = cursor.fetchall()
    finally:
        close_connection(connection)
    return render_template("donor_dashboard.html", listings=listings)


@app.route("/donor/past")
@role_required("donor")
def past_donations():
    connection = None
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT f.*,
                       (SELECT COUNT(*) FROM food_requests r
                        WHERE r.listing_id = f.listing_id AND r.status = 'pending')
                       AS pending_request_count,
                       CASE
                           WHEN f.pickup_deadline <= NOW()
                                AND f.status IN ('available', 'reserved')
                           THEN 'expired'
                           ELSE f.status
                       END AS display_status
                FROM food_listings f
                WHERE f.donor_id = %s
                  AND (
                      f.pickup_deadline <= NOW()
                      OR f.status IN ('collected', 'expired', 'cancelled')
                  )
                ORDER BY f.created_at DESC
                """,
                (session["user_id"],),
            )
            listings = cursor.fetchall()
    finally:
        close_connection(connection)
    return render_template("past_donations.html", listings=listings)


@app.route("/recipient")
@role_required("recipient")
def recipient_dashboard():
    country = request.args.get("country", "").strip()
    city = request.args.get("city", "").strip()
    search = request.args.get("search", "").strip()
    show_all = request.args.get("show_all") == "1"

    # Keep the initial Find Food page empty until the recipient chooses to
    # show all listings or submits a search/filter.
    browsing_requested = show_all or bool(country or city or search)
    listings = []

    if browsing_requested:
        conditions = [
            "f.status = 'available'",
            "f.available_quantity > 0",
            "f.pickup_deadline > NOW()",
        ]
        params = []
        if country:
            conditions.append("LOWER(f.country) = LOWER(%s)")
            params.append(country)
        if city:
            conditions.append("LOWER(f.city) = LOWER(%s)")
            params.append(city)
        if search:
            conditions.append("(f.food_name LIKE %s OR f.description LIKE %s OR f.category LIKE %s)")
            term = f"%{search}%"
            params.extend([term, term, term])

        connection = None
        try:
            connection = get_db()
            with connection.cursor() as cursor:
                cursor.execute(
                    f"""
                    SELECT f.*, u.full_name AS donor_name, u.organization_name
                    FROM food_listings f
                    JOIN users u ON f.donor_id = u.user_id
                    WHERE {' AND '.join(conditions)}
                    ORDER BY f.created_at DESC
                    """,
                    tuple(params),
                )
                listings = cursor.fetchall()
        finally:
            close_connection(connection)

    return render_template(
        "recipient_dashboard.html",
        listings=listings,
        country_filter=country,
        city_filter=city,
        search_filter=search,
        browsing_requested=browsing_requested,
        show_all=show_all,
    )


@app.route("/create-listing", methods=["GET", "POST"])
@role_required("donor")
def create_listing():
    if request.method == "POST":
        food_name = request.form.get("food_name", "").strip()
        description = request.form.get("description", "").strip() or None
        category = request.form.get("category", "").strip()
        unit = request.form.get("unit", "").strip()
        pickup_address = request.form.get("pickup_address", "").strip()
        country = request.form.get("country", "").strip()
        city = request.form.get("city", "").strip()
        locality = request.form.get("locality", "").strip()
        pickup_deadline = request.form.get("pickup_deadline", "").strip()
        prepared_at_text = request.form.get("prepared_at", "").strip()

        try:
            quantity = Decimal(request.form.get("quantity", "0").strip())
            if not quantity.is_finite() or quantity <= 0:
                raise ValueError
            deadline = datetime.fromisoformat(pickup_deadline)
            if deadline <= datetime.now():
                raise ValueError
            prepared_at = datetime.fromisoformat(prepared_at_text) if prepared_at_text else None
            if prepared_at and prepared_at > datetime.now():
                raise ValueError
        except (ValueError, TypeError):
            flash("Enter a positive quantity, a valid preparation time, and a future pickup deadline.", "danger")
            return render_template("create_listing.html")

        if not all([food_name, category, unit, pickup_address, country, city, locality]):
            flash("Please complete all required fields.", "danger")
            return render_template("create_listing.html")

        connection = None
        try:
            connection = get_db()
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO food_listings
                        (donor_id, food_name, description, category, quantity,
                         available_quantity, unit, prepared_at, pickup_deadline,
                         pickup_address, country, city, locality, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'available')
                    """,
                    (
                        session["user_id"], food_name, description, category,
                        quantity, quantity, unit, prepared_at, deadline,
                        pickup_address, country, city, locality
                    ),
                )
            connection.commit()
            flash("Food listing created successfully.", "success")
            return redirect(url_for("donor_dashboard"))
        except Exception:
            if connection:
                connection.rollback()
            app.logger.exception("Creating food listing failed")
            flash("Could not create the listing. Please try again.", "danger")
        finally:
            close_connection(connection)
    return render_template("create_listing.html")


@app.route("/donor/listing/<int:listing_id>/edit", methods=["GET", "POST"])
@role_required("donor")
def edit_listing(listing_id):
    connection = None
    listing = None

    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT *
                FROM food_listings
                WHERE listing_id = %s AND donor_id = %s
                """,
                (listing_id, session["user_id"]),
            )
            listing = cursor.fetchone()

        if not listing:
            flash("Donation listing not found.", "danger")
            return redirect(url_for("donor_dashboard"))

        if listing["status"] not in ("available", "reserved") or listing["pickup_deadline"] <= datetime.now():
            flash("Only active donations can be edited.", "warning")
            return redirect(url_for("past_donations"))

        if request.method == "POST":
            food_name = request.form.get("food_name", "").strip()
            description = request.form.get("description", "").strip() or None
            category = request.form.get("category", "").strip()
            unit = request.form.get("unit", "").strip()
            pickup_address = request.form.get("pickup_address", "").strip()
            country = request.form.get("country", "").strip()
            city = request.form.get("city", "").strip()
            locality = request.form.get("locality", "").strip()
            deadline_text = request.form.get("pickup_deadline", "").strip()
            prepared_text = request.form.get("prepared_at", "").strip()

            try:
                quantity = float(request.form.get("quantity", "0"))
                if not math.isfinite(quantity) or quantity <= 0:
                    raise ValueError
                deadline = datetime.fromisoformat(deadline_text)
                if deadline <= datetime.now():
                    raise ValueError
                prepared_at = datetime.fromisoformat(prepared_text) if prepared_text else None
                if prepared_at and prepared_at > datetime.now():
                    raise ValueError
            except (ValueError, TypeError):
                flash("Enter a positive quantity, a valid preparation time, and a future pickup deadline.", "danger")
                return render_template("edit_listing.html", listing=listing)

            if not all([food_name, category, unit, pickup_address, country, city, locality]):
                flash("Please complete all required fields.", "danger")
                return render_template("edit_listing.html", listing=listing)

            connection.begin()
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT quantity, available_quantity, status, pickup_deadline
                    FROM food_listings
                    WHERE listing_id = %s AND donor_id = %s
                    FOR UPDATE
                    """,
                    (listing_id, session["user_id"]),
                )
                current = cursor.fetchone()
                if not current:
                    connection.rollback()
                    flash("Donation listing not found.", "danger")
                    return redirect(url_for("donor_dashboard"))
                if current["status"] not in ("available", "reserved") or current["pickup_deadline"] <= datetime.now():
                    connection.rollback()
                    flash("This donation is no longer active and cannot be edited.", "warning")
                    return redirect(url_for("past_donations"))

                committed_quantity = float(current["quantity"]) - float(current["available_quantity"])
                if quantity + 1e-9 < committed_quantity:
                    connection.rollback()
                    flash(
                        f"Total quantity cannot be less than {committed_quantity:g} {unit}, "
                        "because that amount is already reserved or collected.",
                        "danger",
                    )
                    listing.update({
                        "food_name": food_name,
                        "description": description,
                        "category": category,
                        "unit": unit,
                        "quantity": quantity,
                        "prepared_at": prepared_at,
                        "pickup_deadline": deadline,
                        "pickup_address": pickup_address,
                        "country": country,
                        "city": city,
                        "locality": locality,
                    })
                    return render_template("edit_listing.html", listing=listing)

                new_available_quantity = quantity - committed_quantity
                new_status = "available" if new_available_quantity > 0 else "reserved"
                cursor.execute(
                    """
                    UPDATE food_listings
                    SET food_name = %s, description = %s, category = %s,
                        quantity = %s, available_quantity = %s, unit = %s,
                        prepared_at = %s, pickup_deadline = %s,
                        pickup_address = %s, country = %s, city = %s,
                        locality = %s, status = %s
                    WHERE listing_id = %s AND donor_id = %s
                    """,
                    (
                        food_name, description, category, quantity,
                        new_available_quantity, unit, prepared_at, deadline,
                        pickup_address, country, city, locality, new_status,
                        listing_id, session["user_id"],
                    ),
                )
            connection.commit()
            flash("Donation updated successfully.", "success")
            return redirect(url_for("donor_dashboard"))

    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Editing donation listing failed")
        flash("Could not update this donation. Please try again.", "danger")
    finally:
        close_connection(connection)

    return render_template("edit_listing.html", listing=listing)


@app.route("/donor/listing/<int:listing_id>/cancel", methods=["POST"])
@role_required("donor")
def cancel_listing(listing_id):
    connection = None
    try:
        connection = get_db()
        connection.begin()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT listing_id, status, pickup_deadline
                FROM food_listings
                WHERE listing_id = %s AND donor_id = %s
                FOR UPDATE
                """,
                (listing_id, session["user_id"]),
            )
            listing = cursor.fetchone()
            if not listing:
                connection.rollback()
                flash("Donation listing not found.", "danger")
                return redirect(url_for("donor_dashboard"))
            if listing["status"] not in ("available", "reserved") or listing["pickup_deadline"] <= datetime.now():
                connection.rollback()
                flash("Only active donations can be cancelled.", "warning")
                return redirect(url_for("past_donations"))

            cursor.execute(
                """
                UPDATE food_requests
                SET status = 'cancelled', updated_at = NOW()
                WHERE listing_id = %s AND status IN ('pending', 'approved')
                """,
                (listing_id,),
            )
            cursor.execute(
                """
                UPDATE collections c
                JOIN food_requests r ON c.request_id = r.request_id
                SET c.collection_status = 'missed'
                WHERE r.listing_id = %s
                  AND r.status = 'cancelled'
                  AND c.collection_status = 'pending'
                """,
                (listing_id,),
            )
            cursor.execute(
                """
                UPDATE food_listings
                SET status = 'cancelled', available_quantity = 0
                WHERE listing_id = %s AND donor_id = %s
                """,
                (listing_id, session["user_id"]),
            )
        connection.commit()
        flash("Donation cancelled. Outstanding requests were cancelled and the history was preserved.", "success")
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Cancelling donation listing failed")
        flash("Could not cancel this donation. Please try again.", "danger")
    finally:
        close_connection(connection)

    return redirect(url_for("donor_dashboard"))


@app.route("/listing/<int:listing_id>")
@role_required("recipient")
def listing_detail(listing_id):
    connection = None
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT f.*, u.full_name AS donor_name, u.organization_name
                FROM food_listings f
                JOIN users u ON f.donor_id = u.user_id
                WHERE f.listing_id = %s
                """,
                (listing_id,),
            )
            listing = cursor.fetchone()
    finally:
        close_connection(connection)

    if not listing:
        flash("That food listing could not be found.", "danger")
        return redirect(url_for("recipient_dashboard"))
    return render_template("listing_detail.html", listing=listing)


@app.route("/listing/<int:listing_id>/request", methods=["POST"])
@role_required("recipient")
def request_food(listing_id):
    try:
        requested_quantity = Decimal(request.form.get("requested_quantity", "0").strip())
        if not requested_quantity.is_finite() or requested_quantity <= 0:
            raise ValueError
    except (TypeError, ValueError, InvalidOperation, AttributeError):
        flash("Enter a valid positive quantity.", "danger")
        return redirect(url_for("listing_detail", listing_id=listing_id))

    connection = None
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT listing_id, donor_id, available_quantity, unit, status, pickup_deadline
                FROM food_listings
                WHERE listing_id = %s
                FOR UPDATE
                """,
                (listing_id,),
            )
            listing = cursor.fetchone()
            if (
                not listing
                or listing["donor_id"] == session["user_id"]
                or listing["status"] != "available"
                or listing["pickup_deadline"] <= datetime.now()
                or requested_quantity > listing["available_quantity"]
            ):
                connection.rollback()
                flash("This listing is unavailable or there is not enough quantity remaining.", "danger")
                return redirect(url_for("recipient_dashboard"))

            cursor.execute(
                """
                SELECT request_id
                FROM food_requests
                WHERE listing_id = %s AND recipient_id = %s
                  AND status IN ('pending', 'approved')
                LIMIT 1
                """,
                (listing_id, session["user_id"]),
            )
            existing = cursor.fetchone()
            if existing:
                connection.rollback()
                flash("You already have an active request for this listing.", "warning")
                return redirect(url_for("my_requests"))

            cursor.execute(
                """
                INSERT INTO food_requests
                    (listing_id, recipient_id, requested_quantity, status, requested_at, updated_at)
                VALUES (%s, %s, %s, 'pending', NOW(), NOW())
                """,
                (listing_id, session["user_id"], requested_quantity),
            )
            cursor.execute(
                """
                UPDATE food_listings
                SET status = CASE WHEN available_quantity <= %s
                                  THEN 'reserved' ELSE status END,
                    available_quantity = available_quantity - %s
                WHERE listing_id = %s
                """,
                (requested_quantity, requested_quantity, listing_id),
            )
        connection.commit()
        flash("Request submitted. The quantity is reserved while the donor reviews it.", "success")
        return redirect(url_for("my_requests"))
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Food request failed")
        flash("Could not submit the request. Please try again.", "danger")
        return redirect(url_for("recipient_dashboard"))
    finally:
        close_connection(connection)


@app.route("/my-requests")
@role_required("recipient")
def my_requests():
    connection = None
    requests_list = []
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT r.request_id, r.requested_quantity, r.status, r.requested_at,
                       r.updated_at, f.food_name, f.category, f.unit, f.pickup_address,
                       f.pickup_deadline, f.status AS listing_status,
                       u.full_name AS donor_name, u.phone AS donor_phone
                FROM food_requests r
                JOIN food_listings f ON r.listing_id = f.listing_id
                JOIN users u ON f.donor_id = u.user_id
                WHERE r.recipient_id = %s
                  AND r.status IN ('pending', 'approved')
                  AND f.status IN ('available', 'reserved')
                  AND f.pickup_deadline > NOW()
                ORDER BY r.requested_at DESC
                """,
                (session["user_id"],),
            )
            requests_list = cursor.fetchall()
    finally:
        close_connection(connection)

    return render_template(
        "my_requests.html",
        requests=requests_list,
        page_title="My Requests",
        subtitle="Track requests waiting for a decision or awaiting collection.",
        active_tab="current"
    )

@app.route("/past-requests")
@role_required("recipient")
def past_requests():
    connection = None
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT r.request_id, r.requested_quantity, r.status, r.requested_at,
                       r.updated_at, f.food_name, f.category, f.unit, f.pickup_address,
                       f.pickup_deadline, f.status AS listing_status,
                       u.full_name AS donor_name,
                       CASE
                           WHEN r.status IN ('collected', 'rejected', 'cancelled') THEN r.status
                           WHEN f.status = 'cancelled' THEN 'donation cancelled'
                           WHEN f.status = 'collected' THEN 'donation collected'
                           WHEN f.status = 'expired' OR f.pickup_deadline <= NOW() THEN 'expired'
                           ELSE r.status
                       END AS display_status
                FROM food_requests r
                JOIN food_listings f ON r.listing_id = f.listing_id
                JOIN users u ON f.donor_id = u.user_id
                WHERE r.recipient_id = %s
                  AND (
                      r.status IN ('collected', 'rejected', 'cancelled')
                      OR f.status IN ('cancelled', 'collected', 'expired')
                      OR f.pickup_deadline <= NOW()
                  )
                ORDER BY r.requested_at DESC
                """,
                (session["user_id"],),
            )
            requests_list = cursor.fetchall()
    finally:
        close_connection(connection)
    return render_template("past_requests.html", requests=requests_list, page_title="Past Requests", subtitle="Review collected, rejected, cancelled, expired, or otherwise inactive requests.", active_tab="past")


@app.route("/donor/requests")
@role_required("donor")
def donor_requests():
    connection = None
    selected_listing_id = request.args.get("listing_id", type=int)
    selected_listing = None
    requests_list = []

    try:
        connection = get_db()
        with connection.cursor() as cursor:
            if selected_listing_id is not None:
                cursor.execute(
                    """
                    SELECT listing_id, food_name
                    FROM food_listings
                    WHERE listing_id = %s AND donor_id = %s
                    """,
                    (selected_listing_id, session["user_id"]),
                )
                selected_listing = cursor.fetchone()

                if not selected_listing:
                    flash("That donation could not be found.", "warning")
                    return redirect(url_for("donor_requests"))

                cursor.execute(
                    """
                    SELECT r.request_id, r.requested_quantity, r.status, r.requested_at,
                           f.listing_id, f.food_name, f.unit, f.pickup_address,
                           f.pickup_deadline, u.full_name AS recipient_name,
                           u.organization_name AS recipient_organization,
                           u.phone AS recipient_phone
                    FROM food_requests r
                    JOIN food_listings f ON r.listing_id = f.listing_id
                    JOIN users u ON r.recipient_id = u.user_id
                    WHERE f.donor_id = %s AND f.listing_id = %s
                    ORDER BY r.requested_at DESC
                    """,
                    (session["user_id"], selected_listing_id),
                )
            else:
                cursor.execute(
                    """
                    SELECT r.request_id, r.requested_quantity, r.status, r.requested_at,
                           f.listing_id, f.food_name, f.unit, f.pickup_address,
                           f.pickup_deadline, u.full_name AS recipient_name,
                           u.organization_name AS recipient_organization,
                           u.phone AS recipient_phone
                    FROM food_requests r
                    JOIN food_listings f ON r.listing_id = f.listing_id
                    JOIN users u ON r.recipient_id = u.user_id
                    WHERE f.donor_id = %s
                    ORDER BY r.requested_at DESC
                    """,
                    (session["user_id"],),
                )

            requests_list = cursor.fetchall()

    finally:
        close_connection(connection)

    return render_template(
        "donor_requests.html",
        requests=requests_list,
        selected_listing=selected_listing,
    )

@app.route("/donor/requests/<int:request_id>/<action>", methods=["POST"])
@role_required("donor")
def handle_food_request(request_id, action):
    if action not in ("approve", "reject"):
        flash("Invalid request action.", "danger")
        return redirect(url_for("donor_requests"))

    connection = None
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT r.request_id, r.listing_id, r.requested_quantity, r.status,
                       f.donor_id, f.available_quantity, f.status AS listing_status
                FROM food_requests r
                JOIN food_listings f ON r.listing_id = f.listing_id
                WHERE r.request_id = %s
                FOR UPDATE
                """,
                (request_id,),
            )
            item = cursor.fetchone()
            if not item or item["donor_id"] != session["user_id"]:
                connection.rollback()
                flash("Request not found.", "danger")
                return redirect(url_for("donor_requests"))
            if item["status"] != "pending":
                connection.rollback()
                flash("This request has already been processed.", "warning")
                return redirect(url_for("donor_requests"))

            if action == "approve":
                cursor.execute(
                    "UPDATE food_requests SET status = 'approved', updated_at = NOW() WHERE request_id = %s",
                    (request_id,),
                )
                cursor.execute(
                    """
                    INSERT INTO collections (request_id, collected_quantity, collection_status)
                    VALUES (%s, %s, 'pending')
                    """,
                    (request_id, item["requested_quantity"]),
                )
                flash_message = "Request approved. The recipient can now arrange collection."
            else:
                cursor.execute(
                    "UPDATE food_requests SET status = 'rejected', updated_at = NOW() WHERE request_id = %s",
                    (request_id,),
                )
                cursor.execute(
                    """
                    UPDATE food_listings
                    SET available_quantity = available_quantity + %s,
                        status = CASE WHEN status = 'reserved' THEN 'available' ELSE status END
                    WHERE listing_id = %s AND pickup_deadline > NOW()
                    """,
                    (item["requested_quantity"], item["listing_id"]),
                )
                flash_message = "Request rejected and its reserved quantity released."

        connection.commit()
        flash(flash_message, "success")
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Processing food request failed")
        flash("Could not process the request. Please try again.", "danger")
    finally:
        close_connection(connection)
    return redirect(url_for("donor_requests"))


@app.route("/donor/requests/<int:request_id>/collected", methods=["POST"])
@role_required("donor")
def mark_collected(request_id):
    connection = None
    try:
        connection = get_db()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT r.request_id, r.listing_id, r.requested_quantity, r.status,
                       f.donor_id
                FROM food_requests r
                JOIN food_listings f ON r.listing_id = f.listing_id
                WHERE r.request_id = %s
                FOR UPDATE
                """,
                (request_id,),
            )
            item = cursor.fetchone()
            if not item or item["donor_id"] != session["user_id"]:
                connection.rollback()
                flash("Request not found.", "danger")
                return redirect(url_for("donor_requests"))
            if item["status"] != "approved":
                connection.rollback()
                flash("Only approved requests can be marked as collected.", "warning")
                return redirect(url_for("donor_requests"))

            cursor.execute(
                """
                UPDATE food_requests
                SET status = 'collected', updated_at = NOW()
                WHERE request_id = %s
                """,
                (request_id,),
            )
            cursor.execute(
                """
                UPDATE collections
                SET collection_status = 'completed', collected_at = NOW(),
                    collected_quantity = %s
                WHERE request_id = %s
                """,
                (item["requested_quantity"], request_id),
            )
            cursor.execute(
                """
                UPDATE food_listings
                SET status = CASE
                    WHEN available_quantity <= 0 THEN 'collected'
                    ELSE status
                END
                WHERE listing_id = %s
                """,
                (item["listing_id"],),
            )
        connection.commit()
        flash("Collection marked as completed.", "success")
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Marking collection failed")
        flash("Could not update the collection. Please try again.", "danger")
    finally:
        close_connection(connection)
    return redirect(url_for("donor_requests"))


if __name__ == "__main__":
    app.run(debug=False)
