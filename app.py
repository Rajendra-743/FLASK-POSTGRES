# import traceback
# import psycopg2
# import bcrypt
# import jwt
# import time
# from functools import wraps
# from flask import Flask, request, jsonify
# from flask_socketio import SocketIO

# app = Flask(__name__)
# socketio = SocketIO(app, logging=True, cors_allowed_origin='*')
# secret_key = 'EJXMGN_wWDw9IhNx_vIcNHw9I4AcfSY0Q_19n1mz58I'

# # Konfigurasi database
# db_config = {
#     'database': 'Clein',
#     'user': 'ilham',
#     'password': 'rajendra123',
#     'host': 'localhost',
#     'port': 5432
# }

# # Fungsi koneksi ke database
# def get_db_connection():
#     try:
#         connection = psycopg2.connect(**db_config)
#         return connection
#     except Exception as e:
#         print("Database connection error:", e)
#         raise

# def hash_password(password):
#     salt = bcrypt.gensalt()
#     hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
#     return hashed_password.decode('utf-8')

# # Dekorator untuk validasi token JWT
# def token_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = request.headers.get('Authorization')
#         if not token:
#             return jsonify({'message': 'Token is missing'}), 403

#         try:
#             payload = jwt.decode(token.split()[1], secret_key, algorithms=['HS256'])
#             print("Decoded Token Payload:", payload)  # Debug log payload
#         except jwt.ExpiredSignatureError:
#             return jsonify({'message': 'Token has expired'}), 401
#         except jwt.InvalidTokenError:
#             return jsonify({'message': 'Invalid token'}), 403

#         return f(payload, *args, **kwargs)

#     return decorated

# # Fungsi untuk menambah admin baru
# def add_admin(username, password):
#     hashed_password = hash_password(password)
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute(
#             """
#             INSERT INTO admins (admin_username, admin_pass)
#             VALUES (%s, %s)
#             """,
#             (username, hashed_password)
#         )
#         conn.commit()
#         return True
#     except (Exception, psycopg2.DatabaseError) as error:
#         print("Error while adding admin", error)
#         return False
#     finally:
#         if conn:
#             conn.close()

# # Route untuk mengecek semua route yang tersedia
# @app.route('/routes', methods=['GET'])
# def show_routes():
#     routes = []
#     for rule in app.url_map.iter_rules():
#         routes.append({
#             'endpoint': rule.endpoint,
#             'methods': list(rule.methods),
#             'url': str(rule)
#         })
#     return jsonify(routes), 200

# @app.route('/')
# def land():
#     return "Hello, World!"

# # LOGIN ADMIN
# @app.route('/login-admin', methods=['POST'])
# def login_admin():
#     if not request.is_json:
#         return jsonify({'message': 'Unsupported Media Type'}), 415

#     try:
#         data = request.get_json(force=True)
#         username = data.get('username')
#         password = data.get('password')

#         if not username or not password:
#             return jsonify({'message': 'Username and password are required'}), 400

#         conn = get_db_connection()
#         cursor = conn.cursor()

#         cursor.execute(
#             """
#             SELECT id_admin, admin_username, admin_pass
#             FROM admins
#             WHERE admin_username = %s
#             """,
#             (username,)
#         )
#         admin = cursor.fetchone()

#         if admin:
#             hashed_password = admin[2]
#             if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
#                 id_admin, admin_username = admin[0], admin[1]
#                 token = jwt.encode({'id_admin': id_admin, 'exp': time.time() + 3600}, secret_key, algorithm='HS256')

#                 print("Generated Token:", token)  # Debug log token

#                 return jsonify({
#                     'message': 'Login successful',
#                     'id_admin': id_admin,
#                     'admin_username': admin_username,
#                     'token': token
#                 }), 200
#             else:
#                 return jsonify({'message': 'Invalid username or password'}), 401
#         else:
#             return jsonify({'message': 'Invalid username or password'}), 401

#     except Exception as e:
#         print(f"Error during login: {e}")
#         traceback.print_exc()
#         return jsonify({'message': 'Server error', 'error': str(e)}), 500

#     finally:
#         if 'conn' in locals():
#             conn.close()

# # GET DATA USER (User Details)
# @app.route('/user-details', methods=['GET'])
# @token_required
# def user_details(payload):
#     user_id = payload.get('id_admin')  # Ambil id_admin dari token

#     print("User ID from token:", user_id)  # Debug log user_id

#     if user_id is None:
#         return jsonify({'message': 'User ID not found in token'}), 400

#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()

#         # Query data pengguna dari tabel `users` berdasarkan user_id
#         cursor.execute(
#             """
#             SELECT user_id, full_name, email, points
#             FROM users
#             WHERE user_id = %s
#             """,
#             (user_id,)
#         )
        
#         user = cursor.fetchone()
#         print("Query result:", user)  # Debug log hasil query

#         if user:
#             user_id, full_name, email, points = user
#             response = {
#                 'user_id': user_id,
#                 'full_name': full_name,
#                 'email': email,
#                 'points': points
#             }
#             return jsonify(response), 200
#         else:
#             return jsonify({'message': 'User not found'}), 404

#     except Exception as e:
#         print(f"Error: {e}")
#         return jsonify({'message': 'Internal server error', 'error': str(e)}), 500

#     finally:
#         if cursor:
#             cursor.close()
#         if conn:
#             conn.close() 

# # Jalankan aplikasi Flask
# if __name__ == '__main__':
#     app.run(debug=True)

# #! GET PROFILE ADMIN
# @app.route('/user-details', methods=['GET'])
# @token_required
# def user_details(payload):
#     user_id = payload.get('id_admin')  # Ambil id_admin dari token

#     print("User ID from token:", user_id)  # Log user_id

#     if user_id is None:
#         return jsonify({'message': 'User ID not found in token'}), 400

#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()

#         # Query data pengguna dari tabel `users` berdasarkan user_id
#         cursor.execute(
#             """
#             SELECT user_id, full_name, email, points
#             FROM users
#             WHERE user_id = %s
#             """,
#             (user_id,)
#         )
        
#         user = cursor.fetchone()
#         print("Query result:", user)  # Log hasil query

#         if user:
#             user_id, full_name, email, points = user
#             response = {
#                 'user_id': user_id,
#                 'full_name': full_name,
#                 'email': email,
#                 'points': points
#             }
#             return jsonify(response), 200
#         else:
#             print("No user found for user_id:", user_id)  # Log jika tidak ada pengguna ditemukan
#             return jsonify({'message': 'User not found'}), 404

#     except Exception as e:
#         print(f"Error: {e}")
#         return jsonify({'message': 'Internal server error', 'error': str(e)}), 500

#     finally:
#         if cursor:
#             cursor.close()
#         if conn:
#             conn.close()

# #! UPDATE ADMIN
# @app.route('/update-profile', methods=['POST'])
# @token_required
# def edit_profile(payload):
#     data = request.json
#     user_type = data.get('user_type')

#     if user_type != 'admin':
#         return jsonify({'message': 'Invalid user type'}), 400

#     # Validasi input
#     admin_id = data.get('id_admin')
#     new_username = data.get('admin_username')
#     new_email = data.get('admin_email')

#     if not admin_id or not new_username:
#         return jsonify({'message': 'Admin ID and new username are required'}), 400

#     conn = get_db_connection()
#     cursor = conn.cursor()

#     try:
#         cursor.execute(
#             """
#             UPDATE admins
#             SET admin_username = %s,
#                 admin_email = COALESCE(%s, admin_email)
#             WHERE id_admin = %s
#             """,
#             (new_username, new_email, admin_id)
#         )
#         conn.commit()

#         response = {
#             'message': 'Admin profile updated successfully',
#             'updated_username': new_username,
#             'updated_email': new_email
#         }
#         return jsonify(response), 200
#     except Exception as e:
#         conn.rollback()
#         print(f'Error: {e}')
#         response = {'message': 'Failed to update admin profile'}
#         return jsonify(response), 500
#     finally:
#         cursor.close()
#         conn.close()

# #! RESET PASSWORD
# @app.route("/reset-admin-pass", methods=['POST'])
# def reset_admin_pw():
#     print("Reset password endpoint called")  # Tambahkan log untuk debugging
#     data = request.json
#     admin_username = data.get('admin_username')
#     new_pass = data.get('password')

#     if not admin_username or not new_pass:
#         return jsonify({'message': 'Admin username and password are required'}), 400

#     # Hash password baru
#     hashed_new_pass = bcrypt.hashpw(new_pass.encode('utf-8'), bcrypt.gensalt())
#     stored_new_pass = hashed_new_pass.decode('utf-8')

#     conn = get_db_connection()
#     cursor = conn.cursor()

#     try:
#         cursor.execute(
#             """
#             UPDATE admins
#             SET admin_pass = %s
#             WHERE admin_username = %s
#             """,
#             (stored_new_pass, admin_username)
#         )
#         if cursor.rowcount == 0:
#             return jsonify({'message': 'Admin username not found'}), 404
        
#         conn.commit()
#         return jsonify({'message': 'Admin password reset successfully'}), 201

#     except Exception as e:
#         conn.rollback()
#         print(f'Error: {e}')
#         return jsonify({'message': 'Reset admin password failed'}), 500

#     finally:
#         cursor.close()
#         conn.close()

# # @app.route('/user-details', methods=['GET'])
# # def user_details():
# #     token = request.headers.get('Authorization')
# #     print(token)

# #     if token:
# #         try:
# #             payload = jwt.decode(token.split()[1], secret_key, algorithms=['HS256'])

# #             print(payload)

# #             user_id = payload['user_id']
# #             conn = get_db_connection()
# #             cursor = conn.cursor()
# #             cursor.execute(
# #                 """
# #                 SELECT user_id, full_name, points
# #                 FROM users
# #                 WHERE user_id = %s
# #                 """,
# #                 (user_id,)
# #             )
# #             user = cursor.fetchone()

# #             if user:
# #                 user_id, full_name, points = user[0], user[1], user[2]
# #                 response = {
# #                     'user_id': user_id,
# #                     'full_name': full_name,
# #                     'points': points
# #                 }
# #                 return jsonify(response), 200
# #             else:
# #                 return jsonify({'message': 'User not found'}), 404

# #         except jwt.ExpiredSignatureError:
# #             return jsonify({'message': 'Token has expired'}), 401
# #         except jwt.InvalidTokenError:
# #             return jsonify({'message': 'Invalid token'}), 402
# #     else:
# #         return jsonify({'message': 'Token is missing'}), 402
    
# @app.route('/get-barang', methods=['GET'])
# def exchangeable_items():
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()

#         cursor.execute("SELECT * FROM barang_tukar")
#         barang = cursor.fetchall()

#         barang_list = []
#         for barang in barang:
#             barang_data = {
#                 'barang_id': barang[0],
#                 'barang_name': barang[1],
#                 'barang_points': barang[2],
#                 'barang_stok': barang[3],
#                 'barang_image':barang[4]
#             }
#             barang_list.append(barang_data)

#         conn.close()

#         return jsonify(barang_list), 200

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

# @app.route('/get-barang-stock/<int:barang_id>', methods=['GET'])
# def get_barang_stock(barang_id):
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()

#         cursor.execute("SELECT barang_stok FROM barang_tukar WHERE barang_id = %s", (barang_id,))
#         stock = cursor.fetchone()

#         if stock is not None:
#             stock_value = stock[0]
#             conn.close()
#             return jsonify({'barang_id': barang_id, 'barang_stok': stock_value}), 200
#         else:
#             conn.close()
#             return jsonify({'error': 'Product not found'}), 404

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

# @app.route('/get-users', methods=['GET'])
# def get_users():
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()

#         cursor.execute("SELECT * FROM users")
#         users = cursor.fetchall()

#         user_list = []
#         for user in users:
#             user_data = {
#                 'user_id': user[0],
#                 'full_name': user[1],
#                 'username': user[2],
#                 'email': user[3],
#                 'points': user[4],
#             }
#             user_list.append(user_data)


#         return jsonify(user_list), 200

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500
    
# @app.route('/delete-user', methods=['POST'])
# def delete_user():
#     data = request.json
#     user_id = data.get('user_id')
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()

#         cursor.execute(
#             """
#             DELETE FROM users
#             WHERE user_id = %s
#             """,
#             (user_id,)
#         )

#         conn.commit()
#         conn.close()

#         response = {'message': 'User deleted successfully'}
#         return jsonify(response), 200

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500
    
# @app.route('/get-sampah', methods=['GET'])
# def get_sampah():
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()

#         cursor.execute("SELECT * FROM sampah ORDER BY id_sampah  ASC")
#         sampah = cursor.fetchall()

#         sampah_list = []
#         for sampah in sampah:
#             sampah_data = {
#                 'id_sampah': sampah[0],
#                 'nama_sampah': sampah[1],
#                 'ukuran': sampah[2],
#                 'poin_sampah': sampah[3],
#             }
#             sampah_list.append(sampah_data)

#         conn.close()

#         return jsonify(sampah_list), 200

#     except Exception as e:
#         print(f"Error in get_sampah: {str(e)}")
#         traceback.print_exc()
#         return jsonify({'error': 'Internal Server Error'}), 500
    
# @app.route('/update-stok', methods=['POST'])
# def update_stok():
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
#             (barang_stok,barang_id)
#         )

#         conn.commit()
#         conn.close()

#         response = {'message': 'Update stock successfully'}
#         return jsonify(response), 200

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500





# @app.route('/store-transaction', methods=['POST'])
# def store_transaction():
#     data = request.json
#     user_id = data.get('user_id')
#     jumlah_botol = data.get('jumlah_botol')
#     jumlah_poin = data.get('jumlah_poin')
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()

#         cursor.execute(
#             """
#             INSERT INTO transaksi_ubah_botol (user_id, jumlah_botol, jumlah_poin)
#             VALUES (%s, %s, %s)
#             """,
#             (user_id, jumlah_botol, jumlah_poin)
#         )
#         conn.commit()
#         conn.close()
#         response = {'message': 'Transaction stored successfully'}
#         return jsonify(response), 200

#     except Exception as e:
#         print(f"Error in store_transaction: {str(e)}")
#         traceback.print_exc()
#         conn.rollback()
#         response = {'message': 'Failed to store transaction'}
#         return jsonify(response), 500

# @app.route('/update-points', methods=['POST'])
# def update_points():
#     data = request.json
#     user_id = data.get('user_id')
#     points_to_add = data.get('points')

#     conn = get_db_connection()
#     cursor = conn.cursor()

#     try:
#         cursor.execute(
#             """
#             UPDATE users
#             SET points = points + %s
#             WHERE user_id = %s
#             """,
#             (points_to_add, user_id)
#         )
#         conn.commit()
#         response = {'message': 'Points updated successfully'}
#         return jsonify(response), 200
#     except:
#         conn.rollback()
#         response = {'message': 'Failed to update points'}
#         return jsonify(response), 500
#     finally:
#         conn.close()

# @app.route('/get-notifications', methods=['GET'])
# def get_notifications():
#     try:
#         user_id = request.args.get('user_id', type=int)

#         conn = get_db_connection()
#         cursor = conn.cursor()

#         cursor.execute(
#             """
#             SELECT id_t_botol, jumlah_botol, jumlah_poin, tanggal
#             FROM transaksi_ubah_botol
#             WHERE user_id = %s
#             ORDER BY tanggal DESC
#             """,
#             (user_id,)
#         )

#         notifications_botol = cursor.fetchall()

#         cursor.execute(
#             """
#             SELECT id_t_poin, nama_barang, jumlah_barang, jumlah_poin, tanggal, user_id, barang_id, status, alasan
#             FROM transaksi_tukar_point
#             WHERE user_id = %s
#             ORDER BY tanggal DESC
#             """,
#             (user_id,)
#         )

#         notifications_point = cursor.fetchall()

#         notification_list = []
#         for notification in notifications_botol:
#             notification_data = {
#                 'id_t_botol': notification[0],
#                 'type': 'Setor Botol',
#                 'jumlah_botol': notification[1],
#                 'jumlah_poin': notification[2],
#                 'tanggal': notification[3].isoformat(), 
#             }
#             notification_list.append(notification_data)
        
#         for notification in notifications_point:
#             notification_data = {
#                 'id_t_poin': notification[0],
#                 'type': 'Tukar Poin',
#                 'nama_barang' : notification[1],
#                 'jumlah_barang' : notification[2],
#                 'jumlah_point': notification[3],
#                 'tanggal': notification[4].isoformat(),
#                 'user_id': notification[5],
#                 'barang_id': notification[6],
#                 'status': notification[7],
#                 'alasan': notification[8],
#             }
#             notification_list.append(notification_data)

#         notification_list.sort(key=lambda x: x['tanggal'], reverse=True)

#         conn.close()

#         return jsonify(notification_list), 200

#     except Exception as e:
#         print(f"Error in get_notifications: {str(e)}")
#         traceback.print_exc()
#         return jsonify({'error': 'Internal Server Error'}), 500

# @app.route('/get-acc-rewards', methods=['GET'])
# def get_acc_rewards():
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()

#         cursor.execute(
#             """
#             SELECT
#                 users.user_id,
#                 full_name,
#                 username,
#                 email,
#                 points,
#                 id_t_poin,
#                 nama_barang,
#                 jumlah_barang,
#                 jumlah_poin,
#                 tanggal,
#                 barang_id,
#                 status,
#                 alasan
#             FROM
#                 users
#             LEFT JOIN
#                 transaksi_tukar_point ON users.user_id = transaksi_tukar_point.user_id
#             WHERE
#                 users.user_id IN (SELECT user_id FROM transaksi_tukar_point)
#             ORDER BY
#                 tanggal DESC
#             """
#         )

#         acc_reward_list = []

#         for row in cursor.fetchall():
#             acc_reward_data = {
#                 'user_id': row[0],
#                 'full_name': row[1],
#                 'username': row[2],
#                 'email': row[3],
#                 'points': row[4],
#                 'id_t_poin': row[5],
#                 'nama_barang': row[6],
#                 'jumlah_barang': row[7],
#                 'jumlah_point': row[8],
#                 'tanggal': row[9].isoformat() if row[9] is not None else None,
#                 'barang_id': row[10],
#                 'status': row[11],
#                 'alasan': row[12]
#                 }
#             acc_reward_list.append(acc_reward_data)
        
#         conn.close()

#         return jsonify(acc_reward_list), 200

#     except Exception as e:
#         print(f"Error in get_acc_rewards: {str(e)}")
#         traceback.print_exc()
#         return jsonify({'error': 'Internal Server Error'}), 500


# @app.route('/store-exchange-evidence', methods=['POST'])
# def store_exchange_evidence():
#     data = request.json
#     user_id = data.get('user_id')
#     barang_id = data.get('barang_id')
#     total_points = data.get('total_points')
#     exchange_date = data.get('exchange_date')
#     barang_name = data.get('barang_name')
#     jumlah_barang = data.get('jumlah_barang')

#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()

#         cursor.execute(
#             """
#             INSERT INTO transaksi_tukar_point (nama_barang ,jumlah_barang ,
#             jumlah_poin, tanggal, user_id, barang_id)
#             VALUES (%s, %s, %s, %s, %s, %s)
#             """,
#             (barang_name, jumlah_barang, total_points, exchange_date, user_id, barang_id)
#         )
#         conn.commit()
#         conn.close()
#         response = {'message': 'Exchange evidence stored successfully'}
#         return jsonify(response), 200

#     except Exception as e:
#         print(f"Error in store_exchange_evidence: {str(e)}")
#         traceback.print_exc()
#         conn.rollback()
#         response = {'message': 'Failed to store exchange evidence'}
#         return jsonify(response), 500

# @app.route('/accept-exchange', methods=['POST'])
# def accept_exchange():
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()

#         data = request.json
#         id_t_poin = data.get('id_t_poin')

#         cursor.execute(
#             """
#             SELECT *
#             FROM transaksi_tukar_point
#             WHERE id_t_poin = %s
#             """,
#             (id_t_poin,)
#         )

#         transaction_detail = cursor.fetchone()
#         print(transaction_detail)

#         if transaction_detail:
#             cursor.execute(
#                 """
#                 UPDATE transaksi_tukar_point
#                 SET status = 'Diterima'
#                 WHERE id_t_poin = %s
#                 """,
#                 (id_t_poin,)
#             )

#             cursor.execute(
#                 """
#                 UPDATE barang_tukar
#                 SET barang_stok = barang_stok - %s
#                 WHERE barang_id = %s
#                 """,
#                 (transaction_detail[2], transaction_detail[6])
#             )

#             cursor.execute(
#                 """
#                 UPDATE users
#                 SET points = points - %s
#                 WHERE user_id = %s
#                 """,
#                 (transaction_detail[3], transaction_detail[5])
#             )

#             conn.commit()

#             return jsonify({'message': 'Penukaran diterima'}), 200

#         return jsonify({'error': 'Transaksi tidak ditemukan'}), 404

#     except Exception as e:
#         print(f"Error in accept_exchange: {str(e)}")
#         traceback.print_exc()
#         return jsonify({'error': 'Internal Server Error'}), 500

# @app.route('/decline-exchange', methods=['POST'])
# def decline_exchange():
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()

#         data = request.json
#         id_t_poin = data.get('id_t_poin')
#         alasan = data.get('alasan')

#         cursor.execute(
#             """
#             SELECT *
#             FROM transaksi_tukar_point
#             WHERE id_t_poin = %s
#             """,
#             (id_t_poin,)
#         )

#         transaction_detail = cursor.fetchone()

#         if transaction_detail:
#             cursor.execute(
#                 """
#                 UPDATE transaksi_tukar_point
#                 SET status = 'Ditolak', alasan = %s
#                 WHERE id_t_poin = %s
#                 """,
#                 (alasan,id_t_poin)
#             )

#             conn.commit()

#             return jsonify({'message': 'Penukaran ditolak'}), 200

#         return jsonify({'error': 'Transaksi tidak ditemukan'}), 404

#     except Exception as e:
#         print(f"Error in decline_exchange: {str(e)}")
#         traceback.print_exc()
#         return jsonify({'error': 'Internal Server Error'}), 500

# @app.route('/get-totals', methods=['GET'])
# def get_totals():
#     try:
#         user_id = request.args.get('user_id', type=int)
#         conn = get_db_connection()
#         cursor = conn.cursor()

#         cursor.execute("""
#             SELECT COALESCE(SUM(jumlah_poin), 0) AS total_poin, COALESCE(SUM(jumlah_botol), 0) AS total_botol 
#             FROM transaksi_ubah_botol WHERE user_id = %s
#         """,
#         (user_id,)               
#         )
#         result = cursor.fetchone()

#         if result:
#             total_poin, total_botol = result
#             return jsonify({'total_poin': total_poin, 'total_botol': total_botol}), 200
#         else:
#             return jsonify({'error': 'No data found'}), 404
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500
    
# @app.route('/get-sampah-socket', methods=['GET'])
# def get_sampah_socket():
#     global sensor_data
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()

#         cursor.execute("SELECT * FROM sampah WHERE nama_sampah=%s", (sensor_data,))
#         sampah = cursor.fetchall()

#         sampah_list = []
#         for sampah in sampah:
#             sampah_data = {
#                 'id_sampah': sampah[0],
#                 'nama_sampah': sampah[1],
#                 'ukuran': sampah[2],
#                 'poin_sampah': sampah[3],
#             }
#             sampah_list.append(sampah_data)


#         conn.close()

#         sensor_data = None

#         return jsonify(sampah_list), 200

#     except Exception as e:
#         print(f"Error in get_sampah: {str(e)}")
#         traceback.print_exc()
#         return jsonify({'error': 'Internal Server Error'}), 500




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


# if __name__ ==  '__main__': 
#     socketio.run(app, debug=True, host='0.0.0.0')

import traceback
import psycopg2
import bcrypt
import jwt
import time
from functools import wraps
from flask import Flask, request, jsonify

app = Flask(__name__)
secret_key = 'EJXMGN_wWDw9IhNx_vIcNHw9I4AcfSY0Q_19n1mz58I'

#! KONFIGURASI DATABASE
db_config = {
    'database': 'Clein',
    'user': 'ilham',
    'password': 'rajendra123',
    'host': 'localhost',
    'port': 5432
}

#! MENGHUBUNGKAN KE DATABASE
def get_db_connection():
    try:
        return psycopg2.connect(**db_config)
    except Exception as e:
        print("Database connection error:", e)
        raise

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
@app.route('/get-profile', methods=['GET'])
@token_required
def get_profile(payload):
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
@app.route('/update-profile', methods=['POST'])
@token_required
def update_profile(payload):
    admin_id = payload.get('id_admin')  
    data = request.get_json()
    admin_email = data.get('admin_email')
    admin_username = data.get('admin_username')

    if not all([admin_email, admin_username]):
        return jsonify({'message': 'Email dan username tidak boleh kosong'}), 400

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

#! MENGAMBIL DATA USER
@app.route('/user-details', methods=['GET'])
@token_required
def user_details(payload):
    try:

        user_id = payload.get('id_admin')  
        print("User ID from token:", user_id)  


        if not user_id:
            return jsonify({'message': 'User ID not found in token'}), 400


        conn = get_db_connection()
        cursor = conn.cursor()


        cursor.execute(
            """
            SELECT user_id, full_name, username, email, points
            FROM users
            WHERE user_id = %s
            """,
            (user_id,)
        )
        
        
        user = cursor.fetchone()
        print("Query result:", user) 

    
        if user:
            response = {
                'user_id': user[0],
                'full_name': user[1],
                'username': user[2],
                'email': user[3],
                'points': user[4]
            }
            return jsonify(response), 200
        else:
            print("User not found")
            return jsonify({'message': 'User not found'}), 404

    except psycopg2.Error as db_error:
        print(f"Database error: {db_error}")  
        return jsonify({'message': 'Database error', 'error': str(db_error)}), 500

    except Exception as e:
        print(f"Error: {e}")  
        return jsonify({'message': 'Internal server error', 'error': str(e)}), 500

    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()

#! MENGAMBIL SEMUA DATA USER
@app.route('/users-list', methods=['GET'])
@token_required
def users_list(payload):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

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
        return jsonify({'message': 'Internal server error', 'error': str(e)}), 500

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
    
        cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({'message': 'User not found'}), 404

        cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        conn.commit()

        return jsonify({'message': 'User deleted successfully'}), 200

    except psycopg2.Error as db_error:
        print(f"Database error: {db_error}")
        return jsonify({'message': 'Database error', 'error': str(db_error)}), 500

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'message': 'Internal server error', 'error': str(e)}), 500

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

#! MENAMPILKAN SEMUA DATA STOK BARANG
@app.route('/get-barang', methods=['GET'])
def exchangeable_items():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM barang_tukar")
        barang = cursor.fetchall()

        barang_list = []
        for barang in barang:
            barang_data = {
                'barang_id': barang[0],
                'barang_name': barang[1],
                'barang_points': barang[2],
                'barang_stok': barang[3],
                'barang_image':barang[4]
            }
            barang_list.append(barang_data)

        conn.close()

        return jsonify(barang_list), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

#! MENGAMBIL STOK BARANG
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

#! MEMPERBARUI JUMLAH STOK BARANG
@app.route('/update-barang/<int:barang_id>', methods=['PATCH'])
def update_barang(barang_id):
    try:
        data = request.json
        new_stock = data.get('barang_stok')

        if new_stock is None:
            return jsonify({'error': 'Stok baru tidak diberikan'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE barang_tukar 
            SET barang_stok = %s 
            WHERE barang_id = %s
            """,
            (new_stock, barang_id)
        )
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({'error': 'Barang tidak ditemukan'}), 404

        return jsonify({'message': 'Stok berhasil diperbarui'}), 200

    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Database error', 'details': str(e)}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

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

@app.route('/get-notifications', methods=['GET'])
def get_notifications():
    try:
        user_id = request.args.get('user_id', type=int)

        conn = get_db_connection()
        cursor = conn.cursor()

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

        cursor.execute(
            """
            SELECT id_t_poin, nama_barang, jumlah_barang, jumlah_poin, tanggal, user_id, barang_id, status, alasan
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
                'nama_barang' : notification[1],
                'jumlah_barang' : notification[2],
                'jumlah_point': notification[3],
                'tanggal': notification[4].isoformat(),
                'user_id': notification[5],
                'barang_id': notification[6],
                'status': notification[7],
                'alasan': notification[8],
            }
            notification_list.append(notification_data)

        notification_list.sort(key=lambda x: x['tanggal'], reverse=True)

        conn.close()

        return jsonify(notification_list), 200

    except Exception as e:
        print(f"Error in get_notifications: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': 'Internal Server Error'}), 500

#! MENGAMBIL DATA USER, BARANG, PENUKARAN POIN
@app.route('/get-acc-rewards', methods=['GET'])
def get_acc_rewards():
    try:
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
                status,
                alasan
            FROM
                users
            LEFT JOIN
                transaksi_tukar_point ON users.user_id = transaksi_tukar_point.user_id
            WHERE
                users.user_id IN (SELECT user_id FROM transaksi_tukar_point)
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
                'alasan': row[12]
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

@app.route('/store-exchange-evidence', methods=['POST'])
def store_exchange_evidence():
    data = request.json
    user_id = data.get('user_id')
    barang_id = data.get('barang_id')
    total_points = data.get('total_points')
    exchange_date = data.get('exchange_date')
    barang_name = data.get('barang_name')
    jumlah_barang = data.get('jumlah_barang')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO transaksi_tukar_point (nama_barang ,jumlah_barang ,
            jumlah_poin, tanggal, user_id, barang_id)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (barang_name, jumlah_barang, total_points, exchange_date, user_id, barang_id)
        )
        conn.commit()
        conn.close()
        response = {'message': 'Exchange evidence stored successfully'}
        return jsonify(response), 200

    except Exception as e:
        print(f"Error in store_exchange_evidence: {str(e)}")
        traceback.print_exc()
        conn.rollback()
        response = {'message': 'Failed to store exchange evidence'}
        return jsonify(response), 500

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
def accept_exchange():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        data = request.json
        id_t_poin = data.get('id_t_poin')

        cursor.execute(
            """
            SELECT *
            FROM transaksi_tukar_point
            WHERE id_t_poin = %s
            """,
            (id_t_poin,)
        )

        transaction_detail = cursor.fetchone()
        print(transaction_detail)

        if transaction_detail:
            cursor.execute(
                """
                UPDATE transaksi_tukar_point
                SET status = 'Diterima'
                WHERE id_t_poin = %s
                """,
                (id_t_poin,)
            )

            cursor.execute(
                """
                UPDATE barang_tukar
                SET barang_stok = barang_stok - %s
                WHERE barang_id = %s
                """,
                (transaction_detail[2], transaction_detail[6])
            )

            cursor.execute(
                """
                UPDATE users
                SET points = points - %s
                WHERE user_id = %s
                """,
                (transaction_detail[3], transaction_detail[5])
            )

            conn.commit()

            return jsonify({'message': 'Penukaran diterima'}), 200

        return jsonify({'error': 'Transaksi tidak ditemukan'}), 404

    except Exception as e:
        print(f"Error in accept_exchange: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/decline-exchange', methods=['POST'])
def decline_exchange():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        data = request.json
        id_t_poin = data.get('id_t_poin')
        alasan = data.get('alasan')

        cursor.execute(
            """
            SELECT *
            FROM transaksi_tukar_point
            WHERE id_t_poin = %s
            """,
            (id_t_poin,)
        )

        transaction_detail = cursor.fetchone()

        if transaction_detail:
            cursor.execute(
                """
                UPDATE transaksi_tukar_point
                SET status = 'Ditolak', alasan = %s
                WHERE id_t_poin = %s
                """,
                (alasan,id_t_poin)
            )

            conn.commit()

            return jsonify({'message': 'Penukaran ditolak'}), 200

        return jsonify({'error': 'Transaksi tidak ditemukan'}), 404

    except Exception as e:
        print(f"Error in decline_exchange: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/get-totals', methods=['GET'])
def get_totals():
    try:
        user_id = request.args.get('user_id', type=int)
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT COALESCE(SUM(jumlah_poin), 0) AS total_poin, COALESCE(SUM(jumlah_botol), 0) AS total_botol 
            FROM transaksi_ubah_botol WHERE user_id = %s
        """,
        (user_id,)               
        )
        result = cursor.fetchone()

        if result:
            total_poin, total_botol = result
            return jsonify({'total_poin': total_poin, 'total_botol': total_botol}), 200
        else:
            return jsonify({'error': 'No data found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500





#! MENJALANKAN APLIKASI
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
