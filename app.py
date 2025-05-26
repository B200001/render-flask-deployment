import base64
import os
from flask_bcrypt import Bcrypt
from flask import Flask, request, jsonify, Response, abort, send_file
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from pymongo.server_api import ServerApi
import jwt
import datetime
from functools import wraps
from bson import ObjectId
import uuid
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
import datetime
from gridfs import GridFS
from dotenv import load_dotenv
import hashlib
#import gridfs
# from your_database_file import users_collection  # Adjust this import as needed

load_dotenv()
app = Flask(__name__)
CORS(
    app,
    supports_credentials=True,
    origins=["http://localhost:5173"]  # Your frontend URL here
)
bcrypt = Bcrypt(app)


SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
app.config["SECRET_KEY"] = SECRET_KEY
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET')
uri = os.environ.get('MONGO_URI')
jwt = JWTManager(app)  # initialize JWTManager

# ------------------ MongoDB Initialization ------------------

client = MongoClient(uri, server_api=ServerApi('1'))

try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print("MongoDB connection error:", e)

db = client # Database name
collection = client.db.files
comment_collection = client.db.comments

fs = GridFS(client.db)

#fs = gridfs.GridFS(db) # Doc handler

#-----------------------GET USER --------------
def get_user_by_email(email):
    return client.db.users.find_one({'email': email})

# ------------------ Config ------------------

# app.config["SECRET_KEY"] = "7JuFgU1QJg9vjdDp5QRJpyTMpIT9O_ZrJZrQCVhC3bQ"  # Change this in production


# ------------------ JWT Decorator ------------------

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            print('Auth header:', auth_header)
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                print("TOKENNN.........",token)
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            print("DATA.............",data)
            current_user = {"userId": data.get('userId')}
        except Exception as e:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated





# ------------------ Routes ------------------

@app.route("/api/auth/signup", methods=["POST"])
def signup():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid input'}), 400

    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'error': 'All fields are required'}), 400

    if get_user_by_email(email):
        return jsonify({'error': 'Email already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    client.db.users.insert_one({'name': name, 'email': email, 'password': hashed_password})
    return jsonify({'message': 'User registered successfully'}), 201



@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or not data.get("email") or not data.get("password"):
        return jsonify({'error': 'Invalid input'}), 400

    email = data["email"]
    password = data["password"]
    

    user = get_user_by_email(email)  # Make sure this returns a dict-like user
    if user:
        # Hash the input password to compare with the stored one
        # hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        if user and bcrypt.check_password_hash(user['password'], password):
            print("YEEEEEEEEEEEEEEEEEEES")
            access_token = create_access_token(identity={"email": user["email"], "isAdmin": user.get("isAdmin", False)})
            return jsonify(access_token=access_token), 200

    return jsonify({'error': 'Invalid credentials'}), 401

# def login():
#     data = request.get_json()
#     if not data:
#         return jsonify({'error': 'Invalid input'}), 400

#     email = data.get('email')
#     password = data.get('password')

#     user = get_user_by_email(email)
#     if user and bcrypt.check_password_hash(user['password'], password):
#         token = jwt.encode({
#         "email": user["email"],
#         "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
#     }, app.config["SECRET_KEY"])
#         return jsonify({"token": token})
#     return jsonify({'error': 'Invalid credentials'}), 401

    


@app.route("/api/pdf/upload", methods=["POST"])
@jwt_required()
def upload_pdf():
    print("UPLOADING..........")
    try:
        current_user = get_jwt_identity()
        print("✅ JWT identity received:", current_user)
    except Exception as e:
        print("❌ JWT error:", str(e))
        return jsonify({"error": "Invalid token"}), 401
    current_user = get_jwt_identity()
    print("User who is uploading:", current_user)

    uploaded_by = current_user if isinstance(current_user, str) else current_user.get("email")

    # file = request.files.get("pdf")
    # if not file or not file.filename.endswith(".pdf"):
    #     return jsonify({"error": "Only PDF files are allowed"}), 400

    # upload_dir = "uploads"
    # os.makedirs(upload_dir, exist_ok=True)

    # unique_filename = f"{uuid.uuid4()}.pdf"
    # file_path = os.path.join(upload_dir, unique_filename)
    # file.save(file_path)

    # pdf_data = {
    #     "original_filename": file.filename,
    #     "stored_filename": unique_filename,
    #     "filepath": f"/{file_path}",
    #     "uploaded_by": uploaded_by,
    #     "comments": []
    # }

    # db.pdfs.insert_one(pdf_data)

    if 'pdf' not in request.files:
        return jsonify({'error': 'No PDF file part'}), 400
    print(".........", request)
    file = request.files['pdf']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    try:
        pdf_data = file.read()

        # Check file size
        if len(pdf_data) > 16 * 1024 * 1024:
            return jsonify({'error': 'File exceeds 16MB limit'}), 400

        document = {
            "filename": file.filename,
            "content_type": file.content_type,
            "upload_time": datetime.datetime.now(),
            "data": pdf_data,
            "uploaded_by": uploaded_by
        }

        result = collection.insert_one(document)
        # print("result..........", result)
        return jsonify({'message': 'File uploaded successfully', 'file_id': str(result.inserted_id)}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

    #return jsonify({"message": "PDF uploaded successfully"}, current_user), 201



@app.route("/test-upload", methods=["POST"])
# @jwt_required()
def test_upload():
    print("FILES:", request.files)
    print("FORM:", request.form)
    return "OK", 200

from bson import ObjectId

def serialize_pdf(pdf):
    serialized = {}
    for key, value in pdf.items():
        if isinstance(value, ObjectId):
            serialized[key] = str(value)
        elif isinstance(value, bytes):
            # You can either skip it or encode it as base64 if it's needed
            # import base64
            # serialized[key] = base64.b64encode(value).decode('utf-8')
            serialized[key] = None  # or some fallback
        else:
            serialized[key] = value
    return serialized

@app.route("/api/pdf/all", methods=["GET"])
@jwt_required()
def get_pdfs():
    identity = get_jwt_identity()
    email = identity.get("email")

    pdfs_cursor = collection.find({"uploaded_by": email})
    pdfs = [serialize_pdf(pdf) for pdf in pdfs_cursor]
    # print('ssssssss',pdfs)
    # print("......", jsonify(pdfs))

    return pdfs, 200


@app.route('/files/<file_id>')
def get_pdf(file_id):
    print(file_id)
    print(ObjectId(file_id))
    try:
        # Convert the file_id from URL to ObjectId
        oid = ObjectId(file_id)
        
    except Exception:
        return abort(400, "Invalid file ID")

    # Find the document by _id
    doc = collection.find_one({'_id': oid})
    if not doc:
        return abort(404, "File not found")

    # Extract binary PDF data from document
    pdf_data = doc.get('data')
    if not pdf_data:
        return abort(404, "No PDF data found")

    # Return PDF file as response
    return Response(
        pdf_data,
        mimetype=doc.get('content_type', 'application/pdf'),
        headers={
            'Content-Disposition': f'inline; filename="{doc.get("filename", "file.pdf")}"'
        }
    )


# @app.route("/api/shared/<shared_id>", methods=["GET"])
# def get_shared_pdf(file_id):
#     shared_doc = collection.find_one({"shared_id": file_id})
#     if not shared_doc:
#         return jsonify({"error": "Invalid link"}), 404

#     pdf = collection.find_one({"_id": ObjectId(shared_doc["pdf_id"])})
#     if not pdf:
#         return jsonify({"error": "PDF not found"}), 404

#     pdf["_id"] = str(pdf["_id"])
#     return jsonify(pdf)


@app.route("/api/pdf/comment/<pdf_id>", methods=["POST"])
@jwt_required()
def add_comment(pdf_id):
    current_user = get_jwt_identity()
    try:
        object_id = ObjectId(pdf_id)
    except Exception:
        return jsonify({"error": "Invalid PDF ID"}), 400

    data = request.get_json()
    print("DATAAAA", data)
    print('1', pdf_id)
    print('1', data["comment"])
    print('1', current_user.get("email"))
    print('1', datetime.datetime.now())
    # if not data or not data.get("author") or not data.get("text"):
    #     return jsonify({"error": "Missing author or text"}), 400

    comment = {
        "comment_id": str(uuid.uuid4()),
        "pdf_id": pdf_id,
        "text": data["comment"],
        "author": current_user.get("email"),
        "created-At": datetime.datetime.now()
    }

    # print("COMMENT", comment)

    # result = comment_collection.insert_one(
    #     {"_id": object_id},
    #     {"$push": {"comments": comment}},
    #     bypass_document_validation=True,
    #     upsert=True  # creates document if it doesn't exist
    # )
    result = comment_collection.insert_one(
        comment
    )

    return jsonify({"message": "Comment added"}), 200


# @app.route("/api/pdf/comment/<pdf_id>/<comment_id>/reply", methods=["POST"])
# def reply_to_comment(pdf_id, comment_id):
#     data = request.get_json()
#     reply = {
#         "reply_id": str(uuid.uuid4()),
#         "author": data.get("author"),
#         "text": data.get("text")
#     }

#     result = db.pdfs.update_one(
#         {"_id": ObjectId(pdf_id), "comments.comment_id": comment_id},
#         {"$push": {"comments.$.replies": reply}}
#     )

#     if result.modified_count == 1:
#         return jsonify({"message": "Reply added"}), 200
#     return jsonify({"error": "Comment or PDF not found"}), 404


@app.route("/api/pdf/comments/<pdf_id>", methods=["GET"])
def get_comments(pdf_id):
    docs = list(comment_collection.find({"pdf_id": pdf_id}))
    print("PDFs:", docs)
    formatted_comments = [
    {
        "text": c["text"],
        "author": c["author"],
        "created_At": c["created-At"].strftime("%Y-%m-%d %H:%M:%S")  # or use .isoformat()
    }
    for c in docs
    ]
    return jsonify(formatted_comments)

#----------------shared-----------------------

@app.route("/api/pdf/share/<pdf_id>", methods=["GET"])
def share_pdf(pdf_id):
    existing = client.db.shared.find_one({"pdf_id": pdf_id})
    if existing:
        shared_id = existing["shared_id"]
    else:
        shared_id = str(uuid.uuid4())
        client.db.shared.insert_one({
            "shared_id": shared_id,
            "pdf_id": pdf_id
        })

    return jsonify({"share_link": f"/api/sharable/get_pdf/{shared_id}"})

@app.route("/api/sharable/get_pdf/<shared_id>", methods=["GET"])
def get_shared_pdf(shared_id):
    shared = client.db.shared.find_one({"shared_id": shared_id})
    if not shared:
        return abort(404, "Invalid or expired link")

    pdf_id = shared["pdf_id"]
    oid = ObjectId(pdf_id)

    doc = collection.find_one({'_id': oid})
    if not doc:
        return abort(404, "File not found")

    pdf_data = doc.get('data')
    if not pdf_data:
        return abort(404, "No PDF data found")

    return Response(
        pdf_data,
        mimetype=doc.get('content_type', 'application/pdf'),
        headers={
            'Content-Disposition': f'inline; filename="{doc.get("filename", "file.pdf")}"'
        }
    )


@app.route("/api/sharable/get_comments/<shared_id>", methods=["GET"])
def get_shared_comments(shared_id):
    shared = client.db.shared.find_one({"shared_id": shared_id})
    if not shared:
        return jsonify({"error": "Invalid or expired link"}), 404

    pdf_id = shared["pdf_id"]

    comments = list(client.db.comments.find({"pdf_id": pdf_id}))
    for comment in comments:
        comment["_id"] = str(comment["_id"])
        comment["pdf_id"] = str(comment["pdf_id"])
        # Convert created-At to ISO string if it exists and is a BSON datetime
        if "created-At" in comment:
            dt = comment["created-At"]
            # If BSON datetime object
            if hasattr(dt, 'isoformat'):
                comment["created-At"] = dt.isoformat()
            # If stored as int timestamp in milliseconds
            elif isinstance(dt, dict) and "$date" in dt:
                # MongoDB extended JSON format like your example
                millis = dt["$date"].get("$numberLong") if "$numberLong" in dt["$date"] else None
                if millis:
                    ts = int(millis) / 1000
                    comment["created-At"] = datetime.utcfromtimestamp(ts).isoformat()
                else:
                    comment["created-At"] = str(dt)
            else:
                comment["created-At"] = str(dt)
        else:
            comment["created-At"] = None

    return jsonify(comments)


# @app.route("/api/sharable/get_pdf/<shared_id>", methods=["GET"])
# def get_shared_pdf(shared_id):
#     shared = client.db.shared.find_one({"shared_id": shared_id})
#     if not shared:
#         return jsonify({"error": "Invalid or expired link"}), 404

#     pdf_id = shared["pdf_id"]
#     oid = ObjectId(pdf_id)

#     # Fetch PDF document
#     doc = collection.find_one({'_id': oid})
#     if not doc:
#         return jsonify({"error": "File not found"}), 404

#     pdf_data = doc.get('data')
#     if not pdf_data:
#         return jsonify({"error": "No PDF data found"}), 404

#     # Encode binary PDF data as base64
#     encoded_pdf = base64.b64encode(pdf_data).decode("utf-8")

#     # Fetch comments
#     comments = list(client.db.comments.find({"pdf_id": pdf_id}))
#     for comment in comments:
#         comment["_id"] = str(comment["_id"])
#         comment["pdf_id"] = str(comment["pdf_id"])
    
    

#     return jsonify({
#         "pdf": {
#             "filename": doc.get("filename"),
#             "data": encoded_pdf
#         },
#         "comments": comments
#     })

# @app.route("/api/pdf/shared/<shared_id>", methods=["GET"])
# def shared_pdf(shared_id):
    shared_entry = client.db.shared.find_one({"shared_id": shared_id})
    if not shared_entry:
        return jsonify({"error": "Invalid or expired shared link"}), 404

    pdf_id = shared_entry["pdf_id"]
    pdf = client.db.pdfs.find_one({"_id": ObjectId(pdf_id)})

    if not pdf:
        return jsonify({"error": "PDF not found"}), 404

    return Response(
        pdf['file_data'],  # or fetch from GridFS if you're using that
        mimetype='application/pdf',
        headers={"Content-Disposition": f"inline; filename={pdf.get('filename', 'file.pdf')}"}
    )
# @app.route("/api/sharable/get_pdf/<shared_id>", methods=["GET"])
# def get_shared_pdf(shared_id):
#     shared = client.db.shared.find_one({"shared_id": shared_id})
#     if not shared:
#         return jsonify({"error": "Invalid or expired link"}), 404
#     print('sssss',shared)
#     pdf_id = shared["pdf_id"]
#     oid = ObjectId(pdf_id)

#     # Fetch PDF (from collection or GridFS)
#     # pdf = collection.find_one({"_id": ObjectId(pdf_id)})
#     # if not pdf:
#     #     return jsonify({"error": "PDF not found"}), 404

#     # Fetch comments
#     comments = list(client.db.comments.find({"pdf_id": pdf_id}))

#     # Clean comment data (e.g., remove ObjectId)
#     for comment in comments:
#         comment["_id"] = str(comment["_id"])
#         comment["pdf_id"] = str(comment["pdf_id"])

#     doc = collection.find_one({'_id': oid})
#     if not doc:
#         return abort(404, "File not found")

#     # Extract binary PDF data from document
#     pdf_data = doc.get('data')
#     if not pdf_data:
#         return abort(404, "No PDF data found")

#     # Return PDF file as response
#     response_data = Response(
#         pdf_data,
#         mimetype=doc.get('content_type', 'application/pdf'),
#         headers={
#             'Content-Disposition': f'inline; filename="{doc.get("filename", "file.pdf")}"'
#         }
#     )

    # response_data = {
    #     "pdf": {
    #         "filename": pdf.get("filename"),
    #         "data": pdf.get("file_data"),  # or handle GridFS stream
    #     },
    #     "comments": comments
    # }

    return (response_data)



# @app.route('/api/pdf/shared/<file_id>')
# def shared_pdf(file_id):
#     pdf = collection.find_one({'_id': ObjectId(file_id)})
#     if pdf and 'file_data' in pdf:
#         return Response(
#             pdf['file_data'],
#             mimetype='application/pdf',
#             headers={"Content-Disposition": f"inline; filename={pdf.get('filename', 'file.pdf')}"}
#         )
#     return {"error": "File not found"}, 404

# @app.route("/api/share", methods=["POST"])
# def create_share_link():
#     data = request.get_json()
#     pdf_id = data.get("pdf_id")

#     if not pdf_id:
#         return jsonify({"error": "PDF ID required"}), 400

#     shared_id = str(uuid.uuid4())
#     client.db.shared.insert_one({
#         "shared_id": shared_id,
#         "pdf_id": pdf_id,
#         "created_at": datetime.utcnow()
#     })

#     return jsonify({"shared_link": f"/shared/{shared_id}"})

# @app.route("/api/shared/<shared_id>", methods=["GET"])
# def get_shared_pdf(shared_id):
#     shared_doc = client.db.shared.find_one({"shared_id": shared_id})
#     if not shared_doc:
#         return jsonify({"error": "Invalid link"}), 404

#     pdf = client.db.pdfs.find_one({"_id": ObjectId(shared_doc["pdf_id"])})
#     if not pdf:
#         return jsonify({"error": "PDF not found"}), 404

#     pdf["_id"] = str(pdf["_id"])  # Convert ObjectId to string for JSON
#     return jsonify(pdf)


# ------------------ Run App ------------------

if __name__ == "__main__":
    app.run()
