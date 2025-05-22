import traceback
import psycopg2 
import bcrypt
import jwt
import time
import os
from flask import send_from_directory
from flask_socketio import SocketIO
from werkzeug.utils import secure_filename
from psycopg2 import sql
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, request, jsonify

app = Flask(__name__)
socketio = SocketIO(app, logging=True, cors_allowed_origin='*')
secret_key = 'EJXMGN_wWDw9IhNx_vIcNHw9I4AcfSY0Q_19n1mz58I'

#! KONFIGURASI DATABASE
db_config = {
    'database': 'Clein',
    'user': 'ilham',
    'password': 'rajendra123',
    'host': '82.25.108.132', #localhost 
    'port': 5432
}

#! MENGHUBUNGKAN KE DATABASE
def get_db_connection():
    try:
        return psycopg2.connect(**db_config)
    except Exception as e:
        print("Database connection error:", e)
        raise

# Endpoint untuk mengetes koneksi database
@app.route('/test_db')
def test_db_connection():
    try:
        conn = psycopg2.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("SELECT 1;")
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"status": "success", "message": "Connected to the database!"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

#! MENGHASH PASSWORD
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')


#! MENGAMBIL DATA USER
def listen_to_notifications():
    try:
        # Membuat koneksi baru khusus untuk mendengarkan notifikasi
        conn = get_db_connection()
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        # Ganti 'my_channel' dengan nama channel notifikasi yang kamu pakai
        cursor.execute("LISTEN my_channel;")
        print("Listening on channel 'my_channel'...")
        
        while True:
            # Memantau apakah ada data yang masuk (timeout 5 detik)
            if select.select([conn], [], [], 5) == ([], [], []):
                continue
            else:
                conn.poll()
                while conn.notifies:
                    notify = conn.notifies.pop(0)
                    data = notify.payload
                    print(f"Notifikasi diterima: {data}")
                    # Emit notifikasi ke client melalui SocketIO
                    socketio.emit('db_notification', {'data': data})
    except Exception as e:
        print(f"Error in listen_to_notifications: {str(e)}")

#! DEKORATOR VALIDASI TOKEN 
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 403

        try:
            payload = jwt.decode(token.split()[1], secret_key, algorithms=['HS256'])
            print(f"Token payload: {payload}")  
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 403

        return f(payload, *args, **kwargs)
    return decorated

#! VALIDASI TOKEN
@app.route('/validate-token', methods=['GET'])
@token_required
def validate_token(payload):
    return jsonify({'message': 'Token is valid'}), 200

#! LOGIN USER
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        if not data:
            raise ValueError("Invalid JSON format")

        # Tentukan apakah input adalah email atau username
        username_or_email = data.get('email') or data.get('username')
        password = data.get('password')

        if not username_or_email or not password:
            return jsonify({'message': 'Email/Username dan password diperlukan'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # Cek apakah inputnya adalah email atau username
        query = "SELECT user_id, password FROM users WHERE username = %s OR email = %s"
        cursor.execute(query, (username_or_email, username_or_email))
        user = cursor.fetchone()

        if user:
            user_id, hashed_password = user
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                token = jwt.encode({'user_id': user_id, 'exp': time.time() + 3600}, secret_key, algorithm='HS256')
                return jsonify({'message': 'Login berhasil', 'token': token, 'user_id': str(user_id)}), 200
            else:
                return jsonify({'message': 'Email/Username atau password salah'}), 401
        else:
            return jsonify({'message': 'Email/Username atau password salah'}), 401

    except Exception as e:
        return jsonify({'message': 'Kesalahan server', 'error': str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/list-routes', methods=['GET'])
def list_routes():
    import urllib
    output = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods)
        line = urllib.parse.unquote("{:50s} {:20s}".format(rule.endpoint, rule.rule))
        output.append(f"{methods} {line}")
    return "<br>".join(output)

@app.route('/get-user-id', methods=['POST'])
def get_user_id():
    data = request.json
    qr_code = data.get('qr_code')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT user_id FROM users WHERE qr_code = %s", (qr_code,)
        )
        result = cursor.fetchone()

        if result:
            return jsonify({'user_id': result[0]}), 200
        else:
            return jsonify({'message': 'User ID tidak ditemukan'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

#! SIGNUP USER
@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.json
        full_name = data.get('full_name')
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not full_name or not username or not email or not password:
            return jsonify({'message': 'Semua kolom diperlukan'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # Mulai transaksi
        conn.autocommit = False

        # Cek apakah username atau email sudah terdaftar
        cursor.execute("SELECT user_id FROM users WHERE username = %s OR email = %s", (username, email))
        if cursor.fetchone():
            conn.rollback()
            return jsonify({'message': 'Username atau email sudah terdaftar'}), 400

        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        cursor.execute(
            "INSERT INTO users (full_name, username, email, password, points) VALUES (%s, %s, %s, %s, %s) RETURNING user_id",
            (full_name, username, email, hashed_password, 0)
        )

        user_id = cursor.fetchone()[0]

        conn.commit()

        return jsonify({
            'message': 'Signup berhasil',
            'user_id': user_id,
            'full_name': full_name,
            'username': username,
            'email': email
        }), 201

    except Exception as e:
        conn.rollback()
        traceback.print_exc()
        return jsonify({'message': 'Kesalahan server', 'error': str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

#! MENGAMBIL DATA PROFILE USER
@app.route('/get-profile-user', methods=['GET'])
@token_required
def get_profile_user(payload):
    user_id = payload.get('user_id')
    if not user_id:
        return jsonify({'message': 'ID User tidak ditemukan dalam token'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT username, email, full_name, points
            FROM users
            WHERE user_id = %s
            """,
            (user_id,)
        )
        user = cursor.fetchone()

        if user:
            response = {
                'username': user[0],
                'email': user[1],
                'full_name': user[2],
                'points': user[3],  # Tambahkan kolom points
            }
            return jsonify(response), 200
        return jsonify({'message': 'User tidak ditemukan'}), 404

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'message': 'Kesalahan server', 'error': str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

#! UPDATE PROFILE USER 
@app.route('/update-profile-user', methods=['POST'])
@token_required
def update_profile_user(payload):
    user_id = payload.get('user_id')  
    data = request.get_json()
    email = data.get('email')
    full_name = data.get('full_name')
    username = data.get('username')

    if not all([email, full_name, username]):
        return jsonify({'message': 'Email, username dan full name tidak boleh kosong'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE users
            SET email = %s,
                full_name = %s,
                username = %s
            WHERE user_id = %s
            """,
            (email, full_name, username, user_id),
        )
        conn.commit()
        return jsonify({'message': 'Profil berhasil diperbarui'}), 200
    except Exception as e:
        return jsonify({'message': 'Kesalahan server', 'error': str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

#! RESET PASSWORD USER 
@app.route("/reset-user-pass", methods=['POST'])
@token_required
def reset_user_password(payload):
    try:
        user_id = payload.get('user_id')  
        data = request.json
        new_pass = data.get('password')

        if not new_pass:
            return jsonify({'message': 'Password baru tidak boleh kosong'}), 400

        hashed_new_pass = bcrypt.hashpw(new_pass.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE users
            SET password = %s
            WHERE user_id = %s
            """,
            (hashed_new_pass, user_id)
        )

        if cursor.rowcount == 0:
            return jsonify({'message': 'User tidak ditemukan'}), 404

        conn.commit()
        return jsonify({'message': 'Password berhasil diubah'}), 201

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'message': 'Gagal mengubah password', 'error': str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

#! LOGIN ADMIN 
@app.route('/login-admin', methods=['POST'])
def login_admin():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'message': 'Username dan password diperlukan'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id_admin, admin_pass FROM admins WHERE admin_username = %s", (username,))
        admin = cursor.fetchone()

        if admin:
            id_admin, hashed_password = admin
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                token = jwt.encode({'id_admin': str(id_admin), 'exp': time.time() + 3600}, secret_key, algorithm='HS256')
                return jsonify({'message': 'Login berhasil', 'token': token, 'id_admin': str(id_admin)}), 200
            else:
                return jsonify({'message': 'Username atau password salah'}), 401
        else:
            return jsonify({'message': 'Username atau password salah'}), 401

    except Exception as e:
        traceback.print_exc()
        return jsonify({'message': 'Kesalahan server', 'error': str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

#! MENGAMBIL DATA ADMIN 
@app.route('/get-profile-admin', methods=['GET'])
@token_required
def get_profile_admin(payload):
    admin_id = payload.get('id_admin')
    if not admin_id:
        return jsonify({'message': 'ID Admin tidak ditemukan dalam token'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT admin_username, admin_email
            FROM admins
            WHERE id_admin = %s
            """,
            (admin_id,)
        )
        admin = cursor.fetchone()

        if admin:
            response = {
                'admin_username': admin[0],
                'admin_email': admin[1],
            }
            return jsonify(response), 200
        return jsonify({'message': 'Admin tidak ditemukan'}), 404

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'message': 'Kesalahan server', 'error': str(e)}), 500

    finally:
        if 'conn' in locals():
            conn.close()

#! MEMPERBARUI PROFILE ADMIN
@app.route('/update-profile-admin', methods=['POST'])
@token_required
def update_profile_admin(payload):
    admin_id = payload.get('id_admin')  
    data = request.get_json()
    admin_email = data.get('admin_email')
    admin_username = data.get('admin_username')

    if not all([admin_email, admin_username]):
        return jsonify({'message': 'Email, username, dan nama tidak boleh kosong'}), 400
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE admins
            SET admin_email = %s,
                admin_username = %s
            WHERE id_admin = %s
            """,
            (admin_email, admin_username, admin_id),
        )
        conn.commit()
        return jsonify({'message': 'Profil berhasil diperbarui'}), 200
    except Exception as e:
        return jsonify({'message': 'Kesalahan server', 'error': str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

#! RESET PASSWORD ADMIN 
@app.route("/reset-admin-pass", methods=['POST'])
@token_required
def reset_admin_password(payload):
    try:

        admin_id = payload.get('id_admin')  
        data = request.json
        new_pass = data.get('password')

        if not new_pass:
            return jsonify({'message': 'Password baru tidak boleh kosong'}), 400


        hashed_new_pass = bcrypt.hashpw(new_pass.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()


        cursor.execute(
            """
            UPDATE admins
            SET admin_pass = %s
            WHERE id_admin = %s
            """,
            (hashed_new_pass, admin_id)
        )

        if cursor.rowcount == 0:
            return jsonify({'message': 'Admin tidak ditemukan'}), 404

        conn.commit()
        return jsonify({'message': 'Password berhasil diubah'}), 201

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'message': 'Gagal mengubah password', 'error': str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()
#! MENGEHITUNG DATABASE
@app.route('/user-count', methods=['GET'])
@token_required
def admin_user_count(payload):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        conn.close()
        return jsonify({'user_count': count}), 200
    except Exception as e:
        print(f"Error in admin_user_count: {e}")
        traceback.print_exc()
        return jsonify({'message': 'Kesalahan server', 'error': str(e)}), 500
    finally:
        if 'cursor' in locals() and not cursor.closed:
            cursor.close()
        if 'conn' in locals() and not conn.closed:
            conn.close()

@app.route('/users-list', methods=['GET'])
@token_required
def users_list(payload):
    search_query = request.args.get('search', '').strip()
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if search_query:
            # Gunakan LIKE untuk pencarian
            cursor.execute(
                """
                SELECT user_id, full_name, username, email, points
                FROM users
                WHERE LOWER(full_name) LIKE %s OR LOWER(email) LIKE %s
                """,
                (f"%{search_query.lower()}%", f"%{search_query.lower()}%")
            )
        else:
            cursor.execute(
                """
                SELECT user_id, full_name, username, email, points
                FROM users
                """
            )
        users = cursor.fetchall()

        if users:
            users_list = [
                {
                    'user_id': user[0],
                    'full_name': user[1],
                    'username': user[2],
                    'email': user[3],
                    'points': user[4]
                }
                for user in users
            ]
            return jsonify(users_list), 200
        else:
            return jsonify({'message': 'No users found'}), 404

    except psycopg2.Error as db_error:
        print(f"Database error: {db_error}")
        return jsonify({'message': 'Database error', 'error': str(db_error)}), 500

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'message': 'Internal Server Error', 'error': str(e)}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

#! MENGHAPUS DATA USER
@app.route('/users/<int:user_id>', methods=['DELETE'])
@token_required
def delete_user(payload, user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Mulai transaksi
        conn.autocommit = False

        cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()
        if not user:
            conn.rollback()
            return jsonify({'message': 'User tidak ditemukan'}), 404

        cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))

        # Commit transaksi
        conn.commit()

        return jsonify({'message': 'User deleted successfully'}), 200

    except psycopg2.Error as db_error:
        conn.rollback()
        print(f"Database error: {db_error}")
        return jsonify({'message': 'Database error', 'error': str(db_error)}), 500

    except Exception as e:
        conn.rollback()
        print(f"Error: {e}")
        return jsonify({'message': 'Internal Server Error', 'error': str(e)}), 500

    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()

#! MENGAMBIL DATA SAMPAH
@app.route('/get-sampah', methods=['GET'])
def get_sampah():
    try:
        print("Connecting to database...")  
        conn = get_db_connection()
        cursor = conn.cursor()

        print("Executing query...")  
        cursor.execute("SELECT id_sampah, nama_sampah, ukuran, poin_sampah FROM sampah ORDER BY id_sampah ASC")
        sampah = cursor.fetchall()

        print("Query executed. Formatting results...") 
        sampah_list = [
            {
                'id_sampah': item[0],
                'nama_sampah': item[1],
                'ukuran': item[2],
                'poin_sampah': item[3],
            }
            for item in sampah
        ]

        print(f"Sampah List: {sampah_list}")  

        conn.close()
        return jsonify(sampah_list), 200

    except psycopg2.Error as db_error:
        print(f"Database error: {db_error}")
        traceback.print_exc()
        return jsonify({'error': 'Database error', 'details': str(db_error)}), 500

    except Exception as e:
        print(f"Error in get_sampah: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal Server Error', 'details': str(e)}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

#! CREATE BARANG ADMIN
@app.route('/add-stok-barang', methods=['POST'])
@token_required
def add_stok_barang(payload):
    try:
        # Mengambil data form
        title = request.form.get('title')
        point = request.form.get('point')
        stock = request.form.get('stock')

        # Validasi data
        if not title or not point or not stock:
            app.logger.error('Semua field (title, point, stock) diperlukan.')
            return jsonify({'message': 'Semua field (title, point, stock) diperlukan.'}), 400
        try:
            stock = int(stock)
            point = int(point)
        except ValueError:
            app.logger.error('Field stock dan point harus berupa angka.')
            return jsonify({'message': 'Field stock dan point harus berupa angka.'}), 400

        # Menangani upload gambar jika ada
        image = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                image = f"/uploads/{filename}"  # Pastikan selalu diawali dengan '/'
                app.logger.info(f'Gambar disimpan di: {image}')
            else:
                app.logger.error('File gambar tidak valid.')
                return jsonify({'message': 'File gambar tidak valid.'}), 400

        # Menyimpan data ke database
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO barang_tukar (barang_name, barang_points, barang_stok, barang_image)
            VALUES (%s, %s, %s, %s)
            RETURNING barang_id
            """,
            (title, point, stock, image)
        )
        new_barang_id = cursor.fetchone()[0]
        app.logger.info(f'Barang baru ditambahkan dengan ID: {new_barang_id}')
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({
            'message': 'Barang berhasil ditambahkan.',
            'barang_id': new_barang_id,
            'barang_name': title,
            'barang_points': point,
            'barang_stok': stock,
            'barang_image': image
        }), 201

    except Exception as e:
        app.logger.error(f"Error in add_stok_barang: {str(e)}")
        traceback.print_exc()
        return jsonify({'message': 'Terjadi kesalahan server.', 'error': str(e)}), 500

    finally:
        if 'cursor' in locals() and not cursor.closed:
            cursor.close()
        if 'conn' in locals() and not conn.closed:
            conn.close()

#! UPDATE BARANG ADMIN
@app.route('/get-stok-barang', methods=['GET'])
@token_required
def exchangeable_items(payload):
    search_query = request.args.get('search', '').strip()
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if search_query:
            cursor.execute("""
            SELECT * FROM barang_tukar
            WHERE LOWER(barang_name) LIKE %s OR CAST(barang_points AS TEXT) LIKE %s
            """, (f"%{search_query.lower()}%", f"%{search_query.lower()}%"))

        else:
            cursor.execute("SELECT * FROM barang_tukar")

        items = cursor.fetchall()

        barang_list = [{
            'barang_id': item[0],
            'barang_name': item[1],
            'barang_points': item[2],
            'barang_stok': item[3],
            'barang_image': item[4] if item[4] else ''
        } for item in items]

        return jsonify(barang_list), 200

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': str(e)}), 500

    finally:
        if 'conn' in locals():
            conn.close()

#! MENGAMBIL DATA SAMPAH BERDASARKAN ID SAMPAH
@app.route('/get-barang-stock/<int:barang_id>', methods=['GET'])
def get_barang_stock(barang_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT barang_stok FROM barang_tukar WHERE barang_id = %s", (barang_id,))
        stock = cursor.fetchone()

        if stock is not None:
            stock_value = stock[0]
            conn.close()
            return jsonify({'barang_id': barang_id, 'barang_stok': stock_value}), 200
        else:
            conn.close()
            return jsonify({'error': 'Product not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

#! UPDATE BARANG ADMIN
@app.route('/update-stok-barang/<int:barang_id>', methods=['PUT'])
@token_required
def update_stok_barang(payload, barang_id):
    try:
        data = request.json
        title = data.get('judul')
        point = data.get('point')
        stock = data.get('stok')
        image = data.get('gambar')  # Bisa berupa URL atau string kosong/null

        # Validasi input
        if not title or not point or not stock:
            return jsonify({'message': 'Judul, poin, dan stok diperlukan.'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        if image:
            # Jika gambar baru disediakan, update semua field termasuk gambar
            cursor.execute(
                """
                UPDATE barang_tukar
                SET barang_name = %s,
                    barang_points = %s,
                    barang_stok = %s,
                    barang_image = %s
                WHERE barang_id = %s
                """,
                (title, point, stock, image, barang_id)
            )
        else:
            # Jika gambar tidak disediakan, update hanya field lain tanpa mengganti gambar
            cursor.execute(
                """
                UPDATE barang_tukar
                SET barang_name = %s,
                    barang_points = %s,
                    barang_stok = %s
                WHERE barang_id = %s
                """,
                (title, point, stock, barang_id)
            )

        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({'message': 'Barang tidak ditemukan'}), 404

        return jsonify({'message': 'Barang berhasil diupdate'}), 200

    except Exception as e:
        print(f"Error updating product: {e}")
        traceback.print_exc()
        return jsonify({'message': 'Terjadi kesalahan saat mengupdate barang', 'error': str(e)}), 500

    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()

# @app.route('/update-stok-barang', methods=['PATCH'])
# @token_required  # Jika endpoint ini membutuhkan autentikasi
# def update_stok_barang(payload):
#     data = request.json
#     barang_id = data.get('barang_id') 
#     barang_stok = data.get('barang_stok')
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute(
#             """
#             UPDATE barang_tukar
#             SET barang_stok = %s
#             WHERE barang_id = %s
#             """,
#             (barang_stok, barang_id)
#         )
#         conn.commit()
#         conn.close()
#         response = {'message': 'Update stok berhasil'}
#         return jsonify(response), 200
#     except Exception as e:
#         print(f"Error in update_stok_barang: {str(e)}")
#         return jsonify({'error': str(e)}), 500


#! MENGHAPUS STOK BARANG
@app.route('/delete-stok-barang/<int:barang_id>', methods=['DELETE'])
@token_required
def delete_stok_barang(payload, barang_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM barang_tukar WHERE barang_id = %s", (barang_id,))
        conn.commit()

        return jsonify({'message': 'Barang berhasil dihapus'}), 200

    except Exception as e:
        return jsonify({'message': 'Terjadi kesalahan saat menghapus barang', 'error': str(e)}), 500

    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()

#! MENGAMBIL DATA SAMPAH BERDASARKAN NAMA SENSOR    
@app.route('/get-sampah-socket', methods=['GET'])
def get_sampah_socket():
    global sensor_data
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM sampah WHERE nama_sampah=%s", (sensor_data,))
        sampah = cursor.fetchall()

        sampah_list = []
        for sampah in sampah:
            sampah_data = {
                'id_sampah': sampah[0],
                'nama_sampah': sampah[1],
                'ukuran': sampah[2],
                'poin_sampah': sampah[3],
            }
            sampah_list.append(sampah_data)
        conn.close()
        sensor_data = None
        return jsonify(sampah_list), 200
    except Exception as e:
        print(f"Error in get_sampah: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': 'Internal Server Error'}), 500

#! MEMPERBARUI POIN 
@app.route('/update-points', methods=['POST'])
def update_points():
    data = request.json
    user_id = data.get('user_id')
    points_to_add = data.get('points')

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            UPDATE users
            SET points = points + %s
            WHERE user_id = %s
            """,
            (points_to_add, user_id)
        )
        conn.commit()
        response = {'message': 'Points updated successfully'}
        return jsonify(response), 200
    except:
        conn.rollback()
        response = {'message': 'Failed to update points'}
        return jsonify(response), 500
    finally:
        conn.close()

# Tambahkan dekorator @token_required
#! MENGAMBIL NOTIFIKASI USER
@app.route('/get-notifications', methods=['GET'])
@token_required
def get_notifications(payload):
    try:
        user_id = payload.get('user_id')  # Perbaiki di sini
        if user_id is None:
            return jsonify({'message': 'User ID tidak ditemukan dalam token'}), 400

        # Jika perlu, konversi ke integer
        try:
            user_id = int(user_id)
        except ValueError:
            return jsonify({'message': 'User ID harus integer'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # Ambil notifikasi Setor Botol
        cursor.execute(
            """
            SELECT id_t_botol, jumlah_botol, jumlah_poin, tanggal
            FROM transaksi_ubah_botol
            WHERE user_id = %s
            ORDER BY tanggal DESC
            """,
            (user_id,)
        )

        notifications_botol = cursor.fetchall()

        # Ambil notifikasi Tukar Poin
        cursor.execute(
            """
            SELECT id_t_poin, nama_barang, jumlah_barang, jumlah_poin, tanggal, status
            FROM transaksi_tukar_point
            WHERE user_id = %s
            ORDER BY tanggal DESC
            """,
            (user_id,)
        )

        notifications_point = cursor.fetchall()

        notification_list = []
        for notification in notifications_botol:
            notification_data = {
                'id_t_botol': notification[0],
                'type': 'Setor Botol',
                'jumlah_botol': notification[1],
                'jumlah_poin': notification[2],
                'tanggal': notification[3].isoformat(),
            }
            notification_list.append(notification_data)

        for notification in notifications_point:
            notification_data = {
                'id_t_poin': notification[0],
                'type': 'Tukar Poin',
                'nama_barang': notification[1],
                'jumlah_barang': notification[2],
                'jumlah_poin': notification[3],
                'tanggal': notification[4].isoformat(),
                'status': notification[5],
                
            }
            notification_list.append(notification_data)

        # Sort notifikasi berdasarkan tanggal secara descending
        notification_list.sort(key=lambda x: x['tanggal'], reverse=True)

        conn.close()

        return jsonify(notification_list), 200

    except Exception as e:
        print(f"Error in get_notifications: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

#! MENGAMBIL NOTIFIKASI ADMIN
@app.route('/get-low-stock-products', methods=['GET'])
@token_required  # Pastikan hanya admin yang dapat mengakses
def get_low_stock_products(payload):
    try:
        # Verifikasi apakah pengguna adalah admin
        admin_id = payload.get('id_admin')
        if not admin_id:
            return jsonify({'message': 'Akses dilarang'}), 403

        # Ambil threshold dari query parameter, default ke 50 jika tidak disediakan
        threshold = request.args.get('threshold', default=50, type=int)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT barang_id, barang_name, barang_stok, barang_points, barang_image
            FROM barang_tukar
            WHERE barang_stok <= %s
            """,
            (threshold,)
        )
        low_stock_products = cursor.fetchall()

        # Format hasil menjadi list of dicts
        products_list = [
            {
                'barang_id': product[0],
                'barang_name': product[1],
                'barang_stok': product[2],
                'barang_points': product[3],
                'barang_image': product[4] if product[4] else ''
            }
            for product in low_stock_products
        ]

        conn.close()

        return jsonify(products_list), 200

    except Exception as e:
        print(f"Error in get_low_stock_products: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

#! MENGAMBIL DATA TUKAR POIN
@app.route('/get-transaction-tukar-poin', methods=['GET'])
@token_required
def get_transaction_tukar_poin(payload):
    user_id = payload.get('user_id')  # Pastikan menggunakan argumen posisi
    id_t_poin = request.args.get('id_t_poin')  # Mengambil dari query parameter

    if not id_t_poin:
        return jsonify({'message': 'ID transaksi tidak ditemukan'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT nama_barang, jumlah_barang, jumlah_poin, tanggal, status
            FROM transaksi_tukar_point
            WHERE id_t_poin = %s AND user_id = %s
            """,
            (id_t_poin, user_id)  # Pastikan menggunakan tuple
        )

        transaction = cursor.fetchone()

        if transaction:
            response = {
                'nama_barang': transaction[0],
                'jumlah_barang': transaction[1],
                'jumlah_poin': transaction[2],
                'tanggal': transaction[3].isoformat(),  # Pastikan ini dalam format ISO
                'status': transaction[4],
            }
            return jsonify(response), 200
        else:
            return jsonify({'message': 'Transaksi tidak ditemukan'}), 404

    except Exception as e:
        print(f"Error in get_transaction_tukar_poin: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': 'Internal Server Error'}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# ! MENGAMBIL DETAIL TRANSAKSI SETOR BOTOL
@app.route('/get-transaction-setor-botol', methods=['GET'])
@token_required
def get_transaction_setor_botol(payload):
    user_id = payload.get('user_id')
    id_t_botol = request.args.get('id_t_botol')

    if not id_t_botol:
        return jsonify({'message': 'ID transaksi tidak ditemukan'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT jumlah_botol, jumlah_poin, tanggal
            FROM transaksi_ubah_botol
            WHERE id_t_botol = %s AND user_id = %s
            """,
            (id_t_botol, user_id)
        )

        transaction = cursor.fetchone()

        if transaction:
            response = {
                'jumlah_botol': transaction[0],
                'jumlah_poin': transaction[1],
                'tanggal': transaction[2].isoformat() if transaction[2] else None,
            }
            return jsonify(response), 200
        else:
            return jsonify({'message': 'Transaksi tidak ditemukan'}), 404

    except Exception as e:
        print(f"Error in get_transaction_setor_botol: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': 'Internal Server Error'}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()


#! MENGAMBIL DATA USER, BARANG, PENUKARAN POIN
@app.route('/get-acc-rewards', methods=['GET'])
@token_required  # Pastikan hanya admin yang bisa mengakses
def get_acc_rewards(payload):
    try:
        # Optional: Verifikasi apakah user adalah admin
        admin_id = payload.get('id_admin')
        if not admin_id:
            return jsonify({'message': 'Akses dilarang'}), 403

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                users.user_id,
                full_name,
                username,
                email,
                points,
                id_t_poin,
                nama_barang,
                jumlah_barang,
                jumlah_poin,
                tanggal,
                barang_id,
                status
                
            FROM
                users
            LEFT JOIN
                transaksi_tukar_point ON users.user_id = transaksi_tukar_point.user_id
            WHERE
                transaksi_tukar_point.status = 'Belum Dikonfirmasi'
            ORDER BY
                tanggal DESC
            """
        )

        acc_reward_list = []
        for row in cursor.fetchall():
            acc_reward_data = {
                'user_id': row[0],
                'full_name': row[1],
                'username': row[2],
                'email': row[3],
                'points': row[4],
                'id_t_poin': row[5],
                'nama_barang': row[6],
                'jumlah_barang': row[7],
                'jumlah_point': row[8],
                'tanggal': row[9].isoformat() if row[9] is not None else None,
                'barang_id': row[10],
                'status': row[11],
               
            }
            acc_reward_list.append(acc_reward_data)

        conn.close()

        return jsonify(acc_reward_list), 200

    except Exception as e:
        print(f"Error in get_acc_rewards: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': 'Internal Server Error'}), 500


#! MEMPERBARUI STATUS PENUKARAN POIN
@app.route('/update-reward-status', methods=['POST'])
@token_required
def update_reward_status(payload):
    try:
        data = request.json
        id_t_poin = data.get('id_t_poin')
        status = data.get('status')  # 'Accepted' atau 'Rejected'

        if status not in ['Accepted', 'Rejected']:
            return jsonify({'error': 'Invalid status'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE transaksi_tukar_point
            SET status = %s
            WHERE id_t_poin = %s
            """,
            (status, id_t_poin),
        )
        conn.commit()
        return jsonify({'message': 'Status updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

#! STORE EXCHANGE EVIDENCE
@app.route('/store-exchange-evidence', methods=['POST'])
@token_required  # Pastikan endpoint ini dilindungi
def store_exchange_evidence(payload):
    data = request.json
    user_id = payload.get('user_id')
    barang_id = data.get('barang_id')
    nama_barang = data.get('nama_barang')
    jumlah_barang = data.get('jumlah_barang')
    jumlah_poin = data.get('jumlah_poin')  # Pastikan ini adalah jumlah poin yang dikurangi

    print(f"Received exchange request: user_id={user_id}, barang_id={barang_id}, jumlah_poin={jumlah_poin}, jumlah_barang={jumlah_barang}")

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Mulai transaksi
        conn.autocommit = False

        # Mengambil nama, email, dan poin pengguna dari tabel users
        cursor.execute(
            """
            SELECT full_name, email, points
            FROM users
            WHERE user_id = %s
            """,
            (user_id,)
        )
        user = cursor.fetchone()

        if not user:
            conn.rollback()
            print("User tidak ditemukan.")
            return jsonify({'message': 'User tidak ditemukan'}), 404

        full_name, email, current_points = user
        print(f"User points before exchange: {current_points}")

        # Memeriksa apakah pengguna memiliki poin yang cukup
        if current_points < jumlah_poin:
            conn.rollback()
            print("Poin pengguna tidak mencukupi.")
            return jsonify({'message': 'Poin Anda tidak mencukupi untuk penukaran ini.'}), 400

        # Memeriksa apakah stok produk mencukupi
        cursor.execute(
            """
            SELECT barang_stok
            FROM barang_tukar
            WHERE barang_id = %s
            """,
            (barang_id,)
        )
        produk = cursor.fetchone()

        if not produk:
            conn.rollback()
            print("Produk tidak ditemukan.")
            return jsonify({'message': 'Produk tidak ditemukan.'}), 404

        stok_sekarang = produk[0]
        if stok_sekarang < jumlah_barang:
            conn.rollback()
            print("Stok produk tidak mencukupi.")
            return jsonify({'message': 'Stok produk tidak mencukupi untuk penukaran ini.'}), 400

        # Memasukkan data ke tabel transaksi_tukar_point
        cursor.execute(
            """
            INSERT INTO transaksi_tukar_point (nama_barang, jumlah_barang, jumlah_poin, tanggal, user_id, barang_id, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id_t_poin
            """,
            (nama_barang, jumlah_barang, jumlah_poin, datetime.now(), user_id, barang_id, 'Belum Dikonfirmasi')
        )          

        transaksi_id = cursor.fetchone()[0]
        print(f"Transaksi ID: {transaksi_id}")

        # Memasukkan data ke tabel histori_penukaran_point
        action_desc = f"Menukar {jumlah_barang} unit {nama_barang} sebesar {jumlah_poin} poin."
        cursor.execute(
            """
            INSERT INTO histori_penukaran_point (name, email, action_desc, action_date)
            VALUES (%s, %s, %s, NOW())
            """,
            (full_name, email, action_desc),
        )
        print("Histori penukaran poin berhasil ditambahkan.")

        # Mengurangi poin pengguna
        cursor.execute(
            """
            UPDATE users
            SET points = points - %s
            WHERE user_id = %s
            """,
            (jumlah_poin, user_id)
        )
        print(f"Poin pengguna setelah pengurangan: {current_points - jumlah_poin}")

        # Mengurangi stok produk
        cursor.execute(
            """
            UPDATE barang_tukar
            SET barang_stok = barang_stok - %s
            WHERE barang_id = %s
            """,
            (jumlah_barang, barang_id)
        )
        print(f"Stok produk setelah pengurangan: {stok_sekarang - jumlah_barang}")

        # Commit transaksi
        conn.commit()

        response = {
            'message': 'Exchange evidence stored successfully',
            'transaction': {
                'id_t_poin': transaksi_id,  # Pastikan ini adalah int
                'nama_barang': nama_barang,
                'jumlah_barang': jumlah_barang,
                'jumlah_poin': jumlah_poin,
                'tanggal': datetime.now().isoformat(),
                'user_id': user_id,
                'barang_id': barang_id,
                'status': 'Belum Dikonfirmasi',
            
            }
        }
        print("Exchange evidence berhasil disimpan.")
        return jsonify(response), 200

    except Exception as e:
        print(f"Error in store_exchange_evidence: {str(e)}")
        traceback.print_exc()
        if 'conn' in locals():
            conn.rollback()
        response = {'message': 'Failed to store exchange evidence', 'error': str(e)}
        return jsonify(response), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

#! MENGAMBIL DATA HISTORY PENUKARAN POIN
@app.route('/get-history', methods=['GET'])
@token_required
def get_history(payload):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT name, email, action_desc 
            FROM histori_penukaran_point
            ORDER BY action_date DESC
        """)
        history = cursor.fetchall()

        # Debug hasil query
        print(f"Debug /get-history: {history}")

        history_list = [
            {"name": row[0], 
            "email": row[1], 
            "desc": row[2]}
            for row in history
        ]
        return jsonify(history_list), 200
    except Exception as e:
        print(f"Error in /get-history: {e}")  # Log error
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

#! MENAMBAHKAN DATA KE TABEL HISTORY PENUKARAN POIN
@app.route('/add-history', methods=['POST'])
@token_required
def add_history(payload):
    try:
        data = request.json
        name = data.get('name')
        email = data.get('email')
        action_desc = data.get('desc')

        # Debug data yang diterima
        print(f"Debug /add-history: name={name}, email={email}, desc={action_desc}")

        # Validasi input
        if action_desc not in ['menolak', 'menerima']:
            return jsonify({'error': 'action_desc harus "menolak" atau "menerima"'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO histori_penukaran_point (name, email, action_desc, action_date)
            VALUES (%s, %s, %s, NOW())
            """,
            (name, email, action_desc),
        )
        conn.commit()
        print(f"History added successfully: {name}, {email}, {action_desc}")
        return jsonify({'message': 'History added successfully'}), 201
    except Exception as e:
        print(f"Error in /add-history: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

#! MENERIMA TRANSAKSI PENUKARAN POIN 
@app.route('/accept-exchange', methods=['POST'])
@token_required
def accept_exchange(payload):
    try:
        data = request.json
        id_t_poin = data.get('id_t_poin')

        if not id_t_poin:
            return jsonify({'error': 'ID transaksi tidak ditemukan'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # Mulai transaksi
        conn.autocommit = False

        # Mengambil detail transaksi
        cursor.execute(
            """
            SELECT jumlah_barang, jumlah_poin, barang_id, user_id, status, nama_barang
            FROM transaksi_tukar_point
            WHERE id_t_poin = %s
            FOR UPDATE
            """,
            (id_t_poin,)
        )
        transaction_detail = cursor.fetchone()

        if not transaction_detail:
            conn.rollback()
            return jsonify({'error': 'Transaksi tidak ditemukan'}), 404

        jumlah_barang, jumlah_poin, barang_id, user_id, status, nama_barang = transaction_detail

        if status != 'Belum Dikonfirmasi':
            conn.rollback()
            return jsonify({'error': f'Transaksi sudah berstatus {status}'}), 400

        # Memeriksa apakah stok produk masih mencukupi
        cursor.execute(
            """
            SELECT barang_stok
            FROM barang_tukar
            WHERE barang_id = %s
            """,
            (barang_id,)
        )
        produk = cursor.fetchone()

        if not produk:
            conn.rollback()
            return jsonify({'message': 'Produk tidak ditemukan.'}), 404

        stok_sekarang = produk[0]
        if stok_sekarang < jumlah_barang:
            conn.rollback()
            return jsonify({'message': 'Stok produk tidak mencukupi untuk penukaran ini.'}), 400

        # Mengupdate status transaksi menjadi 'Diterima' dan menambahkan tanggal konfirmasi
        cursor.execute(
            """
            UPDATE transaksi_tukar_point
            SET status = 'Diterima', tanggal_konfirmasi = %s
            WHERE id_t_poin = %s
            """,
            (datetime.now(), id_t_poin)
        )

        # Mengurangi poin pengguna
        cursor.execute(
            """
            UPDATE users
            SET points = points - %s
            WHERE user_id = %s
            """,
            (jumlah_poin, user_id)
        )
        print(f"Poin pengguna setelah pengurangan: {jumlah_poin}")

        # Mengurangi stok produk
        cursor.execute(
            """
            UPDATE barang_tukar
            SET barang_stok = barang_stok - %s
            WHERE barang_id = %s
            """,
            (jumlah_barang, barang_id)
        )
        print(f"Stok produk setelah pengurangan: {stok_sekarang - jumlah_barang}")

        # Menambahkan ke histori_penukaran_point
        cursor.execute(
            """
            INSERT INTO histori_penukaran_point (name, email, action_desc, action_date)
            SELECT full_name, email, 'menerima', NOW()
            FROM users
            WHERE user_id = %s
            """,
            (user_id,)
        )
        print("Histori penukaran poin berhasil ditambahkan.")

        # Commit transaksi
        conn.commit()

        return jsonify({'message': 'Penukaran diterima'}), 200

    except Exception as e:
        print(f"Error in accept_exchange: {str(e)}")
        traceback.print_exc()
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'error': 'Internal Server Error'}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

#! MENOLAK TRANSAKSI PENUKARAN POIN
@app.route('/decline-exchange', methods=['POST'])
@token_required
def decline_exchange(payload):
    try:
        data = request.json
        id_t_poin = data.get('id_t_poin')

        if not id_t_poin:
            return jsonify({'error': 'ID transaksi diperlukan'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # Mulai transaksi
        conn.autocommit = False

        # Mengambil status transaksi
        cursor.execute(
            """
            SELECT status, user_id
            FROM transaksi_tukar_point
            WHERE id_t_poin = %s
            FOR UPDATE
            """,
            (id_t_poin,)
        )
        transaction_status = cursor.fetchone()

        if not transaction_status:
            conn.rollback()
            return jsonify({'error': 'Transaksi tidak ditemukan'}), 404

        status, user_id = transaction_status
        if status != 'Belum Dikonfirmasi':
            conn.rollback()
            return jsonify({'error': f'Transaksi sudah berstatus {status}'}), 400

        # Mengupdate status transaksi menjadi 'Ditolak' tanpa alasan
        cursor.execute(
            """
            UPDATE transaksi_tukar_point
            SET status = 'Ditolak', tanggal_konfirmasi = %s
            WHERE id_t_poin = %s
            """,
            (datetime.now(), id_t_poin)
        )

        # Menambahkan ke histori_penukaran_point tanpa alasan
        cursor.execute(
            """
            INSERT INTO histori_penukaran_point (name, email, action_desc, action_date)
            SELECT full_name, email, 'menolak', NOW()
            FROM users
            WHERE user_id = %s
            """,
            (user_id,)
        )
        print("Histori penukaran poin berhasil ditambahkan.")

        # Commit transaksi
        conn.commit()

        return jsonify({'message': 'Penukaran ditolak'}), 200

    except Exception as e:
        print(f"Error in decline_exchange: {str(e)}")
        traceback.print_exc()
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'error': 'Internal Server Error'}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

#! MENGAMBIL POIN USER
@app.route('/get-totals', methods=['GET'])
@token_required
def get_totals(payload):
    try:
        user_id = payload.get('user_id')
        if not user_id:
            return jsonify({'message': 'User ID tidak ditemukan dalam token'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT COALESCE(SUM(jumlah_poin), 0) AS total_poin, 
                    COALESCE(SUM(jumlah_botol), 0) AS total_botol 
            FROM transaksi_ubah_botol 
            WHERE user_id = %s
        """, (user_id,))
        result = cursor.fetchone()

        if result:
            total_poin, total_botol = result
            return jsonify({'total_poin': total_poin, 'total_botol': total_botol}), 200
        else:
            return jsonify({'error': 'Data tidak ditemukan'}), 404
    except Exception as e:
        print(f"Error in get_totals: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route('/berita', methods=['POST'])
@token_required
def create_berita(payload):
    try:
        data = request.json
        judul = data.get('judul')
        konten = data.get('konten')
        gambar = data.get('gambar')  # Optional
        penerbit_berita = data.get('penerbit_berita')

        if not judul or not konten or not penerbit_berita:
            return jsonify({'message': 'Judul, konten, dan penerbit berita diperlukan'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO berita (judul, konten, gambar, penerbit_berita)
            VALUES (%s, %s, %s, %s)
            RETURNING id_berita, tanggal
            """,
            (judul, konten, gambar, penerbit_berita)
        )
        new_berita = cursor.fetchone()
        conn.commit()

        response = {
            'id_berita': new_berita[0],
            'judul': judul,
            'konten': konten,
            'tanggal': new_berita[1].isoformat(),
            'gambar': gambar,
            'penerbit_berita': penerbit_berita
        }

        return jsonify(response), 201

    except Exception as e:
        traceback.print_exc()
        return jsonify({'message': 'Kesalahan server', 'error': str(e)}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# ! READ ALL BERITA
@app.route('/berita', methods=['GET'])
def get_all_berita():
    try:
        page = request.args.get('page', default=1, type=int)
        per_page = request.args.get('per_page', default=10, type=int)
        offset = (page - 1) * per_page

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id_berita, judul, konten, tanggal, gambar, penerbit_berita
            FROM berita
            ORDER BY tanggal DESC
            LIMIT %s OFFSET %s
            """,
            (per_page, offset)
        )
        berita = cursor.fetchall()

        berita_list = [
            {
                'id_berita': b[0],
                'judul': b[1],
                'konten': b[2],
                'tanggal': b[3].isoformat(),
                'gambar': b[4],
                'penerbit_berita': b[5]
            }
            for b in berita
        ]

        return jsonify(berita_list), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({'message': 'Kesalahan server', 'error': str(e)}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# ! READ SINGLE BERITA
@app.route('/berita/<int:id_berita>', methods=['GET'])
def get_berita(id_berita):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id_berita, judul, konten, tanggal, gambar, penerbit_berita
            FROM berita
            WHERE id_berita = %s
            """,
            (id_berita,)
        )
        b = cursor.fetchone()

        if b:
            berita = {
                'id_berita': b[0],
                'judul': b[1],
                'konten': b[2],
                'tanggal': b[3].isoformat(),
                'gambar': b[4],
                'penerbit_berita': b[5]
            }
            return jsonify(berita), 200
        else:
            return jsonify({'message': 'Berita tidak ditemukan'}), 404

    except Exception as e:
        traceback.print_exc()
        return jsonify({'message': 'Kesalahan server', 'error': str(e)}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# ! UPDATE BERITA
@app.route('/berita/<int:id_berita>', methods=['PUT'])
@token_required  # Menggunakan token_required untuk memastikan pengguna terautentikasi
def update_berita(payload, id_berita):
    try:
        data = request.json
        judul = data.get('judul')
        konten = data.get('konten')
        gambar = data.get('gambar')  # Optional
        penerbit_berita = data.get('penerbit_berita')  # Baru

        if not judul or not konten or not penerbit_berita:
            return jsonify({'message': 'Judul, konten, dan penerbit berita diperlukan'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE berita
            SET judul = %s,
                konten = %s,
                gambar = %s,
                penerbit_berita = %s
            WHERE id_berita = %s
            RETURNING tanggal
            """,
            (judul, konten, gambar, penerbit_berita, id_berita)
        )
        updated = cursor.fetchone()
        conn.commit()

        if updated:
            response = {
                'id_berita': id_berita,
                'judul': judul,
                'konten': konten,
                'tanggal': updated[0].isoformat(),
                'gambar': gambar,
                'penerbit_berita': penerbit_berita
            }
            return jsonify(response), 200
        else:
            return jsonify({'message': 'Berita tidak ditemukan'}), 404

    except Exception as e:
        traceback.print_exc()
        return jsonify({'message': 'Kesalahan server', 'error': str(e)}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# ! DELETE BERITA
@app.route('/berita/<int:id_berita>', methods=['DELETE'])
@token_required  # Menggunakan token_required untuk memastikan pengguna terautentikasi
def delete_berita(payload, id_berita):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM berita
            WHERE id_berita = %s
            RETURNING id_berita
            """,
            (id_berita,)
        )
        deleted = cursor.fetchone()
        conn.commit()

        if deleted:
            return jsonify({'message': 'Berita berhasil dihapus'}), 200
        else:
            return jsonify({'message': 'Berita tidak ditemukan'}), 404

    except Exception as e:
        traceback.print_exc()
        return jsonify({'message': 'Kesalahan server', 'error': str(e)}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

#! MENTIMPAN TRANSAKSI PENUKARAN BOTOL
@app.route('/store-transaction', methods=['POST'])
def store_transaction_botol():
    data = request.json
    user_id = data.get('user_id')
    qr_code = data.get('qr_code')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Debug: Print QR Code
        print(f"QR Code diterima: {qr_code}")

        # Validasi barcode menggunakan tabel lokasi_mesin_iot
        cursor.execute("SELECT mesin_id, points FROM lokasi_mesin_iot WHERE barcode = %s", (qr_code,))
        machine = cursor.fetchone()

        if not machine:
            print("⚠️ Barcode tidak valid!")
            return jsonify({'message': 'Barcode tidak valid'}), 400

        mesin_id, points_to_add = machine
        print(f"✅ Barcode valid! Mesin ID: {mesin_id}, Poin: {points_to_add}")

        # Tambahkan poin ke user
        cursor.execute(
            "UPDATE users SET points = points + %s WHERE user_id = %s",
            (points_to_add, user_id)
        )

        # Simpan transaksi dengan mesin_id
        cursor.execute(
            "INSERT INTO transaksi_ubah_botol (user_id, mesin_id, jumlah_poin, jumlah_botol, tanggal) VALUES (%s, %s, %s, %s, NOW())",
            (user_id, mesin_id, points_to_add, 1)
        )

        conn.commit()
        return jsonify({'message': 'Poin berhasil ditambahkan', 'points': points_to_add, 'mesin_id': mesin_id}), 200

    except Exception as e:
        conn.rollback()
        print(f"❌ ERROR: {str(e)}")
        return jsonify({'error': str(e)}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()


#* ENDPOINT UNTUK MENGELOLA DATA LOKASI_MESIN_IOT

#! --- GET ALL --- 
@app.route('/lokasi_mesin_iot', methods=['GET'])
def get_all_lokasi_mesin_iot():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Tambahkan alamat di SELECT
        cursor.execute("""
            SELECT mesin_id, barcode, location, points, latitude, longitude, diperbarui_pada, alamat
            FROM lokasi_mesin_iot
            ORDER BY diperbarui_pada DESC
        """)

        rows = cursor.fetchall()
        lokasi_list = []
        for row in rows:
            lokasi_list.append({
                'mesin_id': row[0],
                'barcode': row[1],
                'location': row[2],
                'points': row[3],
                'latitude': row[4],
                'longitude': row[5],
                'diperbarui_pada': row[6].isoformat() if row[6] else None,
                'alamat': row[7]
            })

        return jsonify(lokasi_list), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({'message': 'Kesalahan server', 'error': str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()


#! --- GET SINGLE (BERDASARKAN mesin_id) --- 
@app.route('/lokasi_mesin_iot/<int:mesin_id>', methods=['GET'])
def get_lokasi_mesin_iot(mesin_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT mesin_id, barcode, location, points, latitude, longitude, diperbarui_pada
            FROM lokasi_mesin_iot
            WHERE mesin_id = %s
        """, (mesin_id,))
        row = cursor.fetchone()
        if row:
            lokasi = {
                'mesin_id': row[0],  # Referencing mesin_id_auto
                'barcode': row[1],
                'location': row[2],
                'points': row[3],
                'latitude': row[4],
                'longitude': row[5],
                'diperbarui_pada': row[6].isoformat() if row[6] else None
            }
            return jsonify(lokasi), 200
        else:
            return jsonify({'message': 'Data lokasi tidak ditemukan'}), 404
    except Exception as e:
        traceback.print_exc()
        return jsonify({'message': 'Kesalahan server', 'error': str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

#! --- CREATE (POST) --- 
@app.route('/lokasi_mesin_iot', methods=['POST'])
@token_required
def create_lokasi_mesin_iot(payload):
    try:
        data = request.json
        barcode = data.get('barcode')
        location = data.get('location')
        points = data.get('points')
        latitude = data.get('latitude')
        longitude = data.get('longitude')

        if not barcode or not location or points is None or latitude is None or longitude is None:
            return jsonify({'message': 'Semua field diperlukan: barcode, location, points, latitude, longitude'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO lokasi_mesin_iot (barcode, location, points, latitude, longitude, diperbarui_pada)
            VALUES (%s, %s, %s, %s, %s, NOW())
            RETURNING mesin_id, diperbarui_pada
        """, (barcode, location, points, latitude, longitude))
        result = cursor.fetchone()
        conn.commit()
        new_id = result[0]
        updated_at = result[1]
        response = {
            'mesin_id': new_id,  # Ensure it's referencing mesin_id_auto
            'barcode': barcode,
            'location': location,
            'points': points,
            'latitude': latitude,
            'longitude': longitude,
            'diperbarui_pada': updated_at.isoformat() if updated_at else None
        }
        return jsonify(response), 201
    except Exception as e:
        traceback.print_exc()
        return jsonify({'message': 'Kesalahan server', 'error': str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

#! --- UPDATE (PUT) --- 

@app.route('/lokasi_mesin_iot/<int:mesin_id>', methods=['PUT'])
@token_required
def update_lokasi_mesin_iot(payload, mesin_id):
    try:
        data = request.json
        barcode = data.get('barcode')
        location = data.get('location')
        points = data.get('points')
        latitude = data.get('latitude')
        longitude = data.get('longitude')

        if not barcode or not location or points is None or latitude is None or longitude is None:
            return jsonify({'message': 'Semua field diperlukan: barcode, location, points, latitude, longitude'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE lokasi_mesin_iot
            SET barcode = %s,
                location = %s,
                points = %s,
                latitude = %s,
                longitude = %s,
                diperbarui_pada = NOW()
            WHERE mesin_id = %s
            RETURNING diperbarui_pada
        """, (barcode, location, points, latitude, longitude, mesin_id))
        result = cursor.fetchone()
        conn.commit()
        if result:
            updated_at = result[0]
            response = {
                'mesin_id': mesin_id,
                'barcode': barcode,
                'location': location,
                'points': points,
                'latitude': latitude,
                'longitude': longitude,
                'diperbarui_pada': updated_at.isoformat() if updated_at else None
            }
            return jsonify(response), 200
        else:
            return jsonify({'message': 'Data lokasi tidak ditemukan'}), 404
    except Exception as e:
        traceback.print_exc()
        return jsonify({'message': 'Kesalahan server', 'error': str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()


#! --- DELETE --- 
@app.route('/lokasi_mesin_iot/<int:mesin_id>', methods=['DELETE'])
@token_required
def delete_lokasi_mesin_iot(payload, mesin_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            DELETE FROM lokasi_mesin_iot
            WHERE mesin_id = %s
            RETURNING mesin_id
        """, (mesin_id,))
        result = cursor.fetchone()
        conn.commit()
        if result:
            return jsonify({'message': 'Data lokasi berhasil dihapus'}), 200
        else:
            return jsonify({'message': 'Data lokasi tidak ditemukan'}), 404
    except Exception as e:
        traceback.print_exc()
        return jsonify({'message': 'Kesalahan server', 'error': str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

#* ENDPOINT UNTUK MENGELOLA DATA LOKASI_PENUKARAN_POIN

#! --- GET ALL ---
@app.route('/lokasi_penukaran_poin', methods=['GET'])
@token_required
def get_all_lokasi(payload):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM lokasi_penukaran_poin ORDER BY diperbarui_pada DESC")
        rows = cursor.fetchall()

        locations = [
            {
                'id_lokasi': row[0],
                'nama_lokasi': row[1],
                'alamat': row[2],
                'latitude': row[3],
                'longitude': row[4],
                'dibuat_pada': row[5].isoformat(),
                'diperbarui_pada': row[6].isoformat()
            }
            for row in rows
        ]

        conn.close()
        return jsonify(locations), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({'message': 'Error fetching data', 'error': str(e)}), 500

#! --- GET SINGLE (BERDASARKAN id_lokasi) ---
@app.route('/lokasi_penukaran_poin/<int:id_lokasi>', methods=['GET'])
@token_required
def get_lokasi_by_id(payload, id_lokasi):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM lokasi_penukaran_poin WHERE id_lokasi = %s", (id_lokasi,))
        row = cursor.fetchone()

        if row:
            location = {
                'id_lokasi': row[0],
                'nama_lokasi': row[1],
                'alamat': row[2],
                'latitude': row[3],
                'longitude': row[4],
                'dibuat_pada': row[5].isoformat(),
                'diperbarui_pada': row[6].isoformat()
            }
            return jsonify(location), 200
        else:
            return jsonify({'message': 'Location not found'}), 404

    except Exception as e:
        traceback.print_exc()
        return jsonify({'message': 'Error fetching location', 'error': str(e)}), 500

#! --- CREATE (POST) ---
@app.route('/lokasi_penukaran_poin', methods=['POST'])
@token_required
def create_lokasi(payload):
    data = request.json
    try:
        # Validate input data
        if not data.get('nama_lokasi') or not data.get('alamat') or not data.get('latitude') or not data.get('longitude'):
            return jsonify({'message': 'Missing required fields'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO lokasi_penukaran_poin (nama_lokasi, alamat, latitude, longitude, dibuat_pada, diperbarui_pada)
            VALUES (%s, %s, %s, %s, NOW(), NOW())
            RETURNING id_lokasi
            """,
            (data['nama_lokasi'], data['alamat'], data['latitude'], data['longitude'])
        )
        new_id = cursor.fetchone()[0]
        conn.commit()
        conn.close()

        return jsonify({'message': 'Location created', 'id_lokasi': new_id}), 201

    except Exception as e:
        traceback.print_exc()
        return jsonify({'message': 'Error creating location', 'error': str(e)}), 500

#! --- UPDATE (PUT) --- 
@app.route('/lokasi_penukaran_poin/<int:id_lokasi>', methods=['PUT'])
@token_required
def update_lokasi(payload, id_lokasi):
    data = request.json
    try:
        # Validate input data
        if not data.get('nama_lokasi') or not data.get('alamat') or not data.get('latitude') or not data.get('longitude'):
            return jsonify({'message': 'Missing required fields'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE lokasi_penukaran_poin
            SET nama_lokasi = %s, alamat = %s, latitude = %s, longitude = %s, diperbarui_pada = NOW()
            WHERE id_lokasi = %s
            """,
            (data['nama_lokasi'], data['alamat'], data['latitude'], data['longitude'], id_lokasi)
        )

        if cursor.rowcount == 0:
            return jsonify({'message': 'Location not found'}), 404

        conn.commit()
        conn.close()
        return jsonify({'message': 'Location updated'}), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({'message': 'Error updating location', 'error': str(e)}), 500

#! --- DELETE ---   
@app.route('/lokasi_penukaran_poin/<int:id_lokasi>', methods=['DELETE'])
@token_required
def delete_lokasi(payload, id_lokasi):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM lokasi_penukaran_poin WHERE id_lokasi = %s", (id_lokasi,))
        
        if cursor.rowcount == 0:
            return jsonify({'message': 'Location not found'}), 404

        conn.commit()
        conn.close()
        return jsonify({'message': 'Location deleted'}), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({'message': 'Error deleting location', 'error': str(e)}), 500

UPLOAD_FOLDER = 'uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

UPLOAD_FOLDER = 'uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#! UPLOAD GAMBAR 
@app.route('/upload-image', methods=['POST'])
def upload_image():
    # Periksa apakah ada file dalam permintaan
    if 'gambar' not in request.files:
        return jsonify({'message': 'No file part'}), 400

    file = request.files['gambar']
    
    # Periksa apakah file memiliki nama
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400

    # Periksa apakah ekstensi file diizinkan
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Buat URL relatif untuk file yang diupload
        file_url = f'/uploads/{filename}'
        return jsonify({'gambar_url': file_url}), 200

    return jsonify({'message': 'File type not allowed'}), 400

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    app.logger.info(f"Serving file: {filename}")
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# active_user = None
# @socketio.on('qr_scan')
# def handle_qr_scan(data):
#     global active_user
#     user_id = data.get('user_id')
#     qr_code = data.get('qr_code')
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute(
#             """
#             SELECT *
#             FROM users
#             WHERE user_id = %s
#             """,
#             (user_id,)
#         )
#         users = cursor.fetchone()

#         if active_user is None and users:
#             if qr_code == "CLEIN_CLEVERBIN_123":
#                 active_user = users
#                 emit('open_bin', broadcast=True)
#                 emit('message', {'message': 'Palang terbuka'}, broadcast=True)
#             else:
#                 emit('message', {'message': 'QR code tidak valid'}, broadcast=True)
#         else:
#             emit('message', {'message': 'Sudah ada pengguna aktif'}, broadcast=True)
    
#     except Exception as e:
#         print(f"Error in handle_qr_scan: {str(e)}")
#         traceback.print_exc()
#         return jsonify({'error': 'Internal Server Error'}), 500

# @socketio.on('join')
# def on_join(data):
#     user_id = data['user_id']
#     join_room(f'user_{user_id}')
#     emit('message', {'message': f'User {user_id} has joined the room user_{user_id}'}, room=f'user_{user_id}')

# @socketio.on('leave')
# def on_leave(data):
#     user_id = data['user_id']
#     leave_room(f'user_{user_id}')
#     emit('message', {'message': f'User {user_id} has left the room user_{user_id}'}, room=f'user_{user_id}')

# @socketio.on('finish')
# def handle_finish(data):
#     global active_user
#     user_id = data.get('user_id')

#     emit('close_bin', room=f'user_{user_id}')
#     emit('message', {'message': 'Pembersihan selesai'}, room=f'user_{user_id}')
#     active_user = None

# @socketio.on('open_close')
# def handle_scanned(data):
#     user_id = data.get('user_id')
#     time.sleep(2)
#     emit('open_bin', room=f'user_{user_id}')
#     time.sleep(2)
#     emit('close_bin', room=f'user_{user_id}')
#     emit('message', {'message': 'botol masuk'}, room=f'user_{user_id}')

# sensor_data = None
# @socketio.on('bottle_size')
# def receive_sensor_data(data):
#     global sensor_data
#     new_sensor_data = data.get('size')
    
#     if new_sensor_data != 'Unknown':
#         sensor_data = new_sensor_data
#         return sensor_data, 200


# @socketio.on('join')
# def on_join(data):
#     user_id = data['user_id']
#     join_room(f'user_{user_id}')
#     emit('message', {'message': f'User {user_id} has joined the room user_{user_id}'}, room=f'user_{user_id}')

# @socketio.on('leave')
# def on_leave(data):
#     user_id = data['user_id']
#     leave_room(f'user_{user_id}')
#     emit('message', {'message': f'User {user_id} has left the room user_{user_id}'}, room=f'user_{user_id}')

# @socketio.on('finish')
# def handle_finish(data):
#     global active_user
#     user_id = data.get('user_id')

#     emit('close_bin', room=f'user_{user_id}')
#     emit('message', {'message': 'Pembersihan selesai'}, room=f'user_{user_id}')
#     active_user = None

# @socketio.on('open_close')
# def handle_scanned(data):
#     user_id = data.get('user_id')
#     time.sleep(2)
#     emit('open_bin', room=f'user_{user_id}')
#     time.sleep(2)
#     emit('close_bin', room=f'user_{user_id}')
#     emit('message', {'message': 'botol masuk'}, room=f'user_{user_id}')

sensor_data = None
@socketio.on('bottle_size')
def receive_sensor_data(data):
    global sensor_data
    new_sensor_data = data.get('size')
    
    if new_sensor_data != 'Unknown':
        sensor_data = new_sensor_data
        return sensor_data, 200

# if __name__ ==  '__main__': 
#     socketio.run(app, host='0.0.0.0', port=5001, debug=True)


# #! MENJALANKAN APLIKASI
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True) 