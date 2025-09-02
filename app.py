
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime
import pandas as pd
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import shutil
import json
import zipfile
from pathlib import Path
import arabic_reshaper
from bidi.algorithm import get_display

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

# Database initialization
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Citizens data table
    c.execute('''CREATE TABLE IF NOT EXISTS citizens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        national_id TEXT UNIQUE NOT NULL,
        phone TEXT NOT NULL,
        status TEXT NOT NULL,
        family_members INTEGER NOT NULL,
        address TEXT NOT NULL,
        notes TEXT,
        added_by TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Settings table
    c.execute('''CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site_name TEXT DEFAULT 'نظام إدارة البيانات',
        site_status TEXT DEFAULT 'active',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Dynamic fields table
    c.execute('''CREATE TABLE IF NOT EXISTS dynamic_fields (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        field_name TEXT UNIQUE NOT NULL,
        field_label TEXT NOT NULL,
        field_type TEXT NOT NULL,
        field_options TEXT,
        is_required INTEGER DEFAULT 0,
        validation_rules TEXT,
        field_order INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Dynamic field values table
    c.execute('''CREATE TABLE IF NOT EXISTS dynamic_field_values (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        citizen_id INTEGER NOT NULL,
        field_id INTEGER NOT NULL,
        field_value TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (citizen_id) REFERENCES citizens(id) ON DELETE CASCADE,
        FOREIGN KEY (field_id) REFERENCES dynamic_fields(id) ON DELETE CASCADE
    )''')
    
    # Create default admin user
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        admin_password = generate_password_hash('admin123')
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)", 
                 ('admin', admin_password))
    
    # Create default settings
    c.execute("SELECT * FROM settings")
    if not c.fetchone():
        c.execute("INSERT INTO settings (site_name, site_status) VALUES (?, ?)", 
                 ('نظام إدارة البيانات', 'active'))
    
    conn.commit()
    conn.close()

# Check if site is active
def is_site_active():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT site_status FROM settings ORDER BY id DESC LIMIT 1")
    result = c.fetchone()
    conn.close()
    return result[0] == 'active' if result else True

# Routes
@app.route('/', methods=['GET', 'POST'])
def index():
    if not is_site_active() and ('user_id' not in session or not session.get('is_admin')):
        return render_template('maintenance.html')
    
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Allow login even during maintenance for potential admin access
    # The maintenance check will be done after login based on user role
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['is_admin'] = user[3]
            return redirect(url_for('dashboard'))
        else:
            flash('اسم المستخدم أو كلمة المرور غير صحيحة', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Check maintenance mode for non-admin users
    if not is_site_active() and not session.get('is_admin'):
        return render_template('maintenance.html')
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get statistics based on user role
    if session.get('is_admin'):
        c.execute("SELECT COUNT(*) FROM citizens")
        total_citizens = c.fetchone()[0]
        
        c.execute("SELECT status, COUNT(*) FROM citizens GROUP BY status")
        status_stats = c.fetchall()
        
        c.execute("SELECT COUNT(*) FROM users")
        total_users = c.fetchone()[0]
    else:
        c.execute("SELECT COUNT(*) FROM citizens WHERE added_by = ?", (session['username'],))
        total_citizens = c.fetchone()[0]
        
        c.execute("SELECT status, COUNT(*) FROM citizens WHERE added_by = ? GROUP BY status", (session['username'],))
        status_stats = c.fetchall()
        
        total_users = 0  # المستخدمون العاديون لا يحتاجون رؤية عدد المستخدمين
    
    conn.close()
    
    return render_template('dashboard.html', 
                         total_citizens=total_citizens,
                         status_stats=status_stats,
                         total_users=total_users)

@app.route('/add_citizen', methods=['GET', 'POST'])
def add_citizen():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        full_name = request.form['full_name']
        national_id = request.form['national_id']
        phone = request.form['phone']
        status = request.form['status']
        family_members = int(request.form['family_members'])
        address = request.form['address']
        notes = request.form.get('notes', '')
        
        # Validation
        if len(national_id) != 11 or not national_id.isdigit():
            flash('الرقم الوطني يجب أن يكون 11 رقم', 'error')
            return render_template('add_citizen.html')
        
        if len(phone) != 10 or not phone.startswith('09') or not phone.isdigit():
            flash('رقم الجوال يجب أن يكون 10 أرقام ويبدأ ب 09', 'error')
            return render_template('add_citizen.html')
        
        if family_members > 50:
            flash('عدد أفراد الأسرة لا يمكن أن يتجاوز 50', 'error')
            return render_template('add_citizen.html')
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        # Check if national_id already exists
        c.execute("SELECT * FROM citizens WHERE national_id = ?", (national_id,))
        if c.fetchone():
            flash('الرقم الوطني مسجل مسبقاً', 'error')
            conn.close()
            return render_template('add_citizen.html')
        
        try:
            c.execute('''INSERT INTO citizens 
                        (full_name, national_id, phone, status, family_members, address, notes, added_by)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                     (full_name, national_id, phone, status, family_members, address, notes, session['username']))
            conn.commit()
            flash('تم إضافة البيانات بنجاح', 'success')
            conn.close()
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash('خطأ في إضافة البيانات', 'error')
            conn.close()
    
    return render_template('add_citizen.html')

@app.route('/view_citizens')
def view_citizens():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    query = "SELECT * FROM citizens WHERE 1=1"
    params = []
    
    # إذا لم يكن مدير، عرض البيانات المضافة من المستخدم فقط
    if not session.get('is_admin'):
        query += " AND added_by = ?"
        params.append(session['username'])
    
    if search:
        query += " AND (full_name LIKE ? OR national_id LIKE ? OR phone LIKE ?)"
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
    
    if status_filter:
        query += " AND status = ?"
        params.append(status_filter)
    
    query += " ORDER BY created_at DESC"
    
    c.execute(query, params)
    all_citizens = c.fetchall()
    
    # Pagination
    offset = (page - 1) * per_page
    citizens = all_citizens[offset:offset + per_page]
    total_pages = (len(all_citizens) + per_page - 1) // per_page
    
    conn.close()
    
    return render_template('view_citizens.html', 
                         citizens=citizens,
                         page=page,
                         total_pages=total_pages,
                         search=search,
                         status_filter=status_filter)

@app.route('/admin')
def admin():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('غير مسموح لك بالوصول لهذه الصفحة', 'error')
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get all users
    c.execute("SELECT id, username, is_admin, created_at FROM users")
    users = c.fetchall()
    
    # Get settings
    c.execute("SELECT * FROM settings ORDER BY id DESC LIMIT 1")
    settings = c.fetchone()
    
    conn.close()
    
    return render_template('admin.html', users=users, settings=settings)

@app.route('/edit_citizen/<int:citizen_id>', methods=['GET', 'POST'])
def edit_citizen(citizen_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # التحقق من صلاحية التعديل
    if session.get('is_admin'):
        c.execute("SELECT * FROM citizens WHERE id = ?", (citizen_id,))
    else:
        c.execute("SELECT * FROM citizens WHERE id = ? AND added_by = ?", (citizen_id, session['username']))
    
    citizen = c.fetchone()
    if not citizen:
        flash('غير مسموح لك بتعديل هذا السجل', 'error')
        conn.close()
        return redirect(url_for('view_citizens'))
    
    if request.method == 'POST':
        full_name = request.form['full_name']
        national_id = request.form['national_id']
        phone = request.form['phone']
        status = request.form['status']
        family_members = int(request.form['family_members'])
        address = request.form['address']
        notes = request.form.get('notes', '')
        
        # Validation
        if len(national_id) != 11 or not national_id.isdigit():
            flash('الرقم الوطني يجب أن يكون 11 رقم', 'error')
            conn.close()
            return render_template('edit_citizen.html', citizen=citizen)
        
        if len(phone) != 10 or not phone.startswith('09') or not phone.isdigit():
            flash('رقم الجوال يجب أن يكون 10 أرقام ويبدأ ب 09', 'error')
            conn.close()
            return render_template('edit_citizen.html', citizen=citizen)
        
        if family_members > 50:
            flash('عدد أفراد الأسرة لا يمكن أن يتجاوز 50', 'error')
            conn.close()
            return render_template('edit_citizen.html', citizen=citizen)
        
        # Check if national_id already exists for another citizen
        c.execute("SELECT * FROM citizens WHERE national_id = ? AND id != ?", (national_id, citizen_id))
        if c.fetchone():
            flash('الرقم الوطني مسجل مسبقاً لمواطن آخر', 'error')
            conn.close()
            return render_template('edit_citizen.html', citizen=citizen)
        
        try:
            c.execute('''UPDATE citizens SET 
                        full_name = ?, national_id = ?, phone = ?, status = ?, 
                        family_members = ?, address = ?, notes = ?
                        WHERE id = ?''',
                     (full_name, national_id, phone, status, family_members, address, notes, citizen_id))
            conn.commit()
            flash('تم تحديث البيانات بنجاح', 'success')
            conn.close()
            return redirect(url_for('view_citizens'))
        except Exception as e:
            flash('خطأ في تحديث البيانات', 'error')
            conn.close()
    
    conn.close()
    return render_template('edit_citizen.html', citizen=citizen)

@app.route('/export')
def export():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('export.html')

@app.route('/export_advanced', methods=['GET', 'POST'])
def export_advanced():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get filter parameters
    status_filters = request.values.getlist('status')
    date_from = request.values.get('date_from')
    date_to = request.values.get('date_to')
    search_text = request.values.get('search_text')
    export_format = request.values.get('format', 'excel')
    grouping = request.values.get('grouping', 'single')
    fields = request.values.getlist('fields')
    all_status = request.values.get('all_status')
    all_fields = request.values.get('all_fields')
    preview = request.values.get('preview')
    
    # Build query
    query = "SELECT * FROM citizens WHERE 1=1"
    params = []
    
    # إذا لم يكن مدير، عرض البيانات المضافة من المستخدم فقط
    if not session.get('is_admin'):
        query += " AND added_by = ?"
        params.append(session['username'])
    
    # Apply filters
    if not all_status and status_filters:
        placeholders = ','.join(['?' for _ in status_filters])
        query += f" AND status IN ({placeholders})"
        params.extend(status_filters)
    
    if date_from:
        query += " AND date(created_at) >= ?"
        params.append(date_from)
    
    if date_to:
        query += " AND date(created_at) <= ?"
        params.append(date_to)
    
    if search_text:
        query += " AND (full_name LIKE ? OR national_id LIKE ?)"
        params.extend([f'%{search_text}%', f'%{search_text}%'])
    
    query += " ORDER BY created_at DESC"
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute(query, params)
    citizens = c.fetchall()
    conn.close()
    
    # If preview requested, return JSON
    if preview:
        preview_html = ""
        if len(citizens) > 0:
            preview_html = "<div class='table-responsive'><table class='table table-sm'>"
            preview_html += "<thead><tr><th>الاسم</th><th>الرقم الوطني</th><th>الحالة</th></tr></thead><tbody>"
            for citizen in citizens[:5]:  # Show first 5 records
                preview_html += f"<tr><td>{citizen[1]}</td><td>{citizen[2]}</td><td>{citizen[4]}</td></tr>"
            if len(citizens) > 5:
                preview_html += f"<tr><td colspan='3'>... و {len(citizens) - 5} سجل آخر</td></tr>"
            preview_html += "</tbody></table></div>"
        
        return jsonify({
            'count': len(citizens),
            'preview': preview_html
        })
    
    if not citizens:
        flash('لا توجد بيانات مطابقة للفلاتر المحددة', 'warning')
        return redirect(url_for('export'))
    
    # Determine fields to export
    field_mapping = {
        'full_name': 'الاسم الثلاثي',
        'national_id': 'الرقم الوطني', 
        'phone': 'الجوال',
        'status': 'الحالة',
        'family_members': 'أفراد الأسرة',
        'address': 'العنوان'
    }
    
    if all_fields or not fields:
        selected_fields = list(field_mapping.keys())
    else:
        selected_fields = fields
    
    # Generate filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if grouping == 'separate' and status_filters and not all_status:
        # Export separate files for each status
        return export_separate_files(citizens, status_filters, export_format, selected_fields, field_mapping, timestamp)
    else:
        # Export single file
        return export_single_file(citizens, export_format, selected_fields, field_mapping, timestamp)

def export_single_file(citizens, export_format, selected_fields, field_mapping, timestamp):
    if export_format == 'excel':
        return export_excel_file(citizens, selected_fields, field_mapping, timestamp)
    elif export_format == 'pdf':
        return export_pdf_file(citizens, selected_fields, field_mapping, timestamp)
    elif export_format == 'csv':
        return export_csv_file(citizens, selected_fields, field_mapping, timestamp)

def export_separate_files(citizens, status_filters, export_format, selected_fields, field_mapping, timestamp):
    # Group citizens by status
    grouped_citizens = {}
    for citizen in citizens:
        status = citizen[4]
        if status not in grouped_citizens:
            grouped_citizens[status] = []
        grouped_citizens[status].append(citizen)
    
    if export_format == 'excel':
        # Create Excel with multiple sheets
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            for status, status_citizens in grouped_citizens.items():
                df_data = prepare_dataframe_data(status_citizens, selected_fields, field_mapping)
                df = pd.DataFrame(df_data[1:], columns=df_data[0])
                df.to_excel(writer, sheet_name=status, index=False)
        
        output.seek(0)
        return send_file(
            output,
            as_attachment=True,
            download_name=f'citizens_by_status_{timestamp}.xlsx',
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
    
    # For PDF and CSV, create a zip file with separate files
    import zipfile
    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for status, status_citizens in grouped_citizens.items():
            if export_format == 'pdf':
                file_content = create_pdf_content(status_citizens, selected_fields, field_mapping)
                zip_file.writestr(f'{status}_{timestamp}.pdf', file_content)
            elif export_format == 'csv':
                file_content = create_csv_content(status_citizens, selected_fields, field_mapping)
                zip_file.writestr(f'{status}_{timestamp}.csv', file_content)
    
    zip_buffer.seek(0)
    
    return send_file(
        zip_buffer,
        as_attachment=True,
        download_name=f'citizens_by_status_{timestamp}.zip',
        mimetype='application/zip'
    )

def prepare_dataframe_data(citizens, selected_fields, field_mapping):
    # Column mapping
    columns = [field_mapping[field] for field in selected_fields]
    field_indices = {
        'full_name': 1,
        'national_id': 2,
        'phone': 3,
        'status': 4,
        'family_members': 5,
        'address': 6
    }
    
    data = [columns]
    for citizen in citizens:
        row = []
        for field in selected_fields:
            row.append(citizen[field_indices[field]])
        data.append(row)
    
    return data

def export_excel_file(citizens, selected_fields, field_mapping, timestamp):
    data = prepare_dataframe_data(citizens, selected_fields, field_mapping)
    df = pd.DataFrame(data[1:], columns=data[0])
    
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='البيانات', index=False)
        
        # Style the worksheet
        worksheet = writer.sheets['البيانات']
        from openpyxl.styles import Font, PatternFill, Alignment
        
        # Header styling
        header_font = Font(bold=True, color='FFFFFF')
        header_fill = PatternFill(start_color='4472C4', end_color='4472C4', fill_type='solid')
        
        for cell in worksheet[1]:
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal='center')
        
        # Auto-adjust column widths
        for column in worksheet.columns:
            max_length = 0
            column_letter = column[0].column_letter
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = min(max_length + 2, 50)
            worksheet.column_dimensions[column_letter].width = adjusted_width
    
    output.seek(0)
    return send_file(
        output,
        as_attachment=True,
        download_name=f'citizens_data_{timestamp}.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

def export_csv_file(citizens, selected_fields, field_mapping, timestamp):
    import csv
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    data = prepare_dataframe_data(citizens, selected_fields, field_mapping)
    for row in data:
        writer.writerow(row)
    
    csv_content = output.getvalue()
    output.close()
    
    csv_buffer = io.BytesIO()
    csv_buffer.write(csv_content.encode('utf-8-sig'))  # UTF-8 with BOM for Excel compatibility
    csv_buffer.seek(0)
    
    return send_file(
        csv_buffer,
        as_attachment=True,
        download_name=f'citizens_data_{timestamp}.csv',
        mimetype='text/csv'
    )

def create_csv_content(citizens, selected_fields, field_mapping):
    import csv
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    data = prepare_dataframe_data(citizens, selected_fields, field_mapping)
    for row in data:
        writer.writerow(row)
    
    content = output.getvalue()
    output.close()
    return content.encode('utf-8-sig')

def export_pdf_file(citizens, selected_fields, field_mapping, timestamp):
    from reportlab.lib.units import cm
    from reportlab.platypus import Spacer, Paragraph
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    import arabic_reshaper
    from bidi.algorithm import get_display
    
    output = io.BytesIO()
    
    # Function to process Arabic text
    def process_arabic_text(text):
        if not text or text == '':
            return ''
        try:
            text = str(text)
            # Process Arabic text for proper display
            reshaped_text = arabic_reshaper.reshape(text)
            bidi_text = get_display(reshaped_text)
            return bidi_text
        except Exception as e:
            # If Arabic processing fails, convert to safe text
            return safe_arabic_to_text(text)
    
    def safe_arabic_to_text(text):
        if not text:
            return ''
        text = str(text)
        # Arabic to readable mapping
        replacements = {
            'ارملة': 'Widow',
            'مطلقة': 'Divorced',
            'اعاقة': 'Disability',
            'كبير بالعمر': 'Elderly',
            'حالة صعبة': 'Difficult Case',
            'الاسم الثلاثي': 'Full Name',
            'الرقم الوطني': 'National ID',
            'الجوال': 'Phone',
            'الحالة': 'Status',
            'أفراد الأسرة': 'Family Members',
            'العنوان': 'Address',
            'الملاحظات': 'Notes'
        }
        
        for arabic, english in replacements.items():
            text = text.replace(arabic, english)
        
        return text
    
    # Configure document
    doc = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
        title='Citizens Data Report'
    )
    
    # Process data
    raw_data = prepare_dataframe_data(citizens, selected_fields, field_mapping)
    processed_data = []
    
    for row in raw_data:
        processed_row = []
        for cell in row:
            try:
                # Try Arabic processing first
                processed_cell = process_arabic_text(cell)
                processed_row.append(processed_cell)
            except:
                # Fallback to safe conversion
                processed_row.append(safe_arabic_to_text(cell))
        processed_data.append(processed_row)
    
    # Create table
    table = Table(processed_data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2E5B88')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('TOPPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8F9FA')]),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    
    # Build document
    story = []
    
    # Add title
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=16,
        alignment=1,
        spaceAfter=20
    )
    
    try:
        title_text = process_arabic_text('تقرير بيانات المواطنين')
        story.append(Paragraph(title_text, title_style))
    except:
        story.append(Paragraph('Citizens Data Report', title_style))
    
    story.append(Spacer(1, 12))
    
    # Add date
    date_style = ParagraphStyle(
        'Date',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        alignment=1,
        spaceAfter=20
    )
    
    try:
        date_text = process_arabic_text(f'تاريخ التقرير: {datetime.now().strftime("%Y-%m-%d")}')
        story.append(Paragraph(date_text, date_style))
    except:
        story.append(Paragraph(f'Report Date: {datetime.now().strftime("%Y-%m-%d")}', date_style))
    
    story.append(Spacer(1, 12))
    story.append(table)
    
    # Build PDF
    doc.build(story)
    output.seek(0)
    
    return send_file(
        output,
        as_attachment=True,
        download_name=f'citizens_data_{timestamp}.pdf',
        mimetype='application/pdf'
    )

def create_pdf_content(citizens, selected_fields, field_mapping):
    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=A4)
    
    data = prepare_dataframe_data(citizens, selected_fields, field_mapping)
    
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
    ]))
    
    doc.build([table])
    content = output.getvalue()
    output.close()
    return content

@app.route('/export_excel')
def export_excel():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('database.db')
    
    # تحديد الاستعلام حسب صلاحية المستخدم
    if session.get('is_admin'):
        df = pd.read_sql_query("SELECT * FROM citizens", conn)
    else:
        df = pd.read_sql_query("SELECT * FROM citizens WHERE added_by = ?", conn, params=[session['username']])
    
    conn.close()
    
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='البيانات', index=False)
    
    output.seek(0)
    
    return send_file(
        output,
        as_attachment=True,
        download_name=f'citizens_data_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Additional routes
@app.route('/citizen_details/<int:citizen_id>')
def citizen_details(citizen_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM citizens WHERE id = ?", (citizen_id,))
    citizen = c.fetchone()
    conn.close()
    
    if citizen:
        return jsonify({
            'full_name': citizen[1],
            'national_id': citizen[2],
            'phone': citizen[3],
            'status': citizen[4],
            'family_members': citizen[5],
            'address': citizen[6],
            'notes': citizen[7],
            'added_by': citizen[8]
        })
    return jsonify({'error': 'Not found'}), 404

@app.route('/delete_citizen/<int:citizen_id>', methods=['DELETE'])
def delete_citizen(citizen_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("DELETE FROM citizens WHERE id = ?", (citizen_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/add_user', methods=['POST'])
def add_user():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    
    username = request.form['username']
    password = request.form['password']
    is_admin = 1 if 'is_admin' in request.form else 0
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    try:
        hashed_password = generate_password_hash(password)
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                 (username, hashed_password, is_admin))
        conn.commit()
        flash('تم إضافة المستخدم بنجاح', 'success')
    except sqlite3.IntegrityError:
        flash('اسم المستخدم موجود مسبقاً', 'error')
    
    conn.close()
    return redirect(url_for('admin'))

@app.route('/delete_user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = ? AND username != 'admin'", (user_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/update_settings', methods=['POST'])
def update_settings():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    
    site_name = request.form['site_name']
    site_status = request.form['site_status']
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("UPDATE settings SET site_name = ?, site_status = ?, updated_at = CURRENT_TIMESTAMP",
             (site_name, site_status))
    conn.commit()
    conn.close()
    
    flash('تم تحديث الإعدادات بنجاح', 'success')
    return redirect(url_for('admin'))

@app.route('/backup')
def backup():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    
    backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    shutil.copy2('database.db', backup_name)
    
    return send_file(backup_name, as_attachment=True)

@app.route('/backup_full')
def backup_full():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_filename = f"full_backup_{timestamp}.zip"
    
    # Create comprehensive backup
    backup_buffer = io.BytesIO()
    with zipfile.ZipFile(backup_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        # Add database
        if os.path.exists('database.db'):
            zip_file.write('database.db', 'database.db')
        
        # Add application files
        zip_file.write('app.py', 'app.py')
        
        # Add templates
        for template_file in os.listdir('templates'):
            if template_file.endswith('.html'):
                zip_file.write(f'templates/{template_file}', f'templates/{template_file}')
        
        # Add static files if they exist
        if os.path.exists('static'):
            for root, dirs, files in os.walk('static'):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, '.')
                    zip_file.write(file_path, arcname)
        
        # Add backup metadata
        metadata = {
            'backup_date': datetime.now().isoformat(),
            'backup_type': 'full',
            'admin_user': session['username'],
            'version': '1.0'
        }
        zip_file.writestr('backup_metadata.json', json.dumps(metadata, ensure_ascii=False, indent=2))
    
    backup_buffer.seek(0)
    
    return send_file(
        backup_buffer,
        as_attachment=True,
        download_name=backup_filename,
        mimetype='application/zip'
    )

@app.route('/restore_backup', methods=['GET', 'POST'])
def restore_backup():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'backup_file' not in request.files:
            flash('لم يتم اختيار ملف', 'error')
            return redirect(url_for('restore_backup'))
        
        file = request.files['backup_file']
        if file.filename == '':
            flash('لم يتم اختيار ملف', 'error')
            return redirect(url_for('restore_backup'))
        
        if file and (file.filename.endswith('.db') or file.filename.endswith('.zip')):
            try:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                
                if file.filename.endswith('.db'):
                    # Backup current database first
                    shutil.copy2('database.db', f'database_backup_before_restore_{timestamp}.db')
                    # Restore database
                    file.save('database.db')
                    flash('تم استعادة قاعدة البيانات بنجاح', 'success')
                
                elif file.filename.endswith('.zip'):
                    # Create backup of current state
                    shutil.copy2('database.db', f'database_backup_before_restore_{timestamp}.db')
                    
                    # Extract and restore from zip
                    temp_path = f'temp_restore_{timestamp}'
                    os.makedirs(temp_path, exist_ok=True)
                    
                    file.save(f'{temp_path}/restore.zip')
                    
                    with zipfile.ZipFile(f'{temp_path}/restore.zip', 'r') as zip_file:
                        zip_file.extractall(temp_path)
                        
                        # Restore database if present
                        if os.path.exists(f'{temp_path}/database.db'):
                            shutil.copy2(f'{temp_path}/database.db', 'database.db')
                    
                    # Cleanup
                    shutil.rmtree(temp_path)
                    flash('تم استعادة النسخة الاحتياطية الكاملة بنجاح', 'success')
                
                return redirect(url_for('admin'))
                
            except Exception as e:
                flash(f'خطأ في استعادة النسخة الاحتياطية: {str(e)}', 'error')
        else:
            flash('نوع الملف غير مدعوم. يجب أن يكون .db أو .zip', 'error')
    
    return render_template('restore_backup.html')

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get user data
    c.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    
    if not user:
        flash('المستخدم غير موجود', 'error')
        conn.close()
        return redirect(url_for('admin'))
    
    # Prevent editing admin user by non-admin or editing self
    if user[1] == 'admin' and session['username'] != 'admin':
        flash('غير مسموح بتعديل المستخدم الرئيسي', 'error')
        conn.close()
        return redirect(url_for('admin'))
    
    if request.method == 'POST':
        new_username = request.form['username']
        new_password = request.form.get('password')
        is_admin = 1 if 'is_admin' in request.form else 0
        
        # Validation
        if len(new_username.strip()) < 3:
            flash('اسم المستخدم يجب أن يكون 3 أحرف على الأقل', 'error')
            conn.close()
            return render_template('edit_user.html', user=user)
        
        # Check if username exists for another user
        c.execute("SELECT id FROM users WHERE username = ? AND id != ?", (new_username, user_id))
        if c.fetchone():
            flash('اسم المستخدم موجود مسبقاً', 'error')
            conn.close()
            return render_template('edit_user.html', user=user)
        
        try:
            if new_password:
                # Update with new password
                hashed_password = generate_password_hash(new_password)
                c.execute("UPDATE users SET username = ?, password = ?, is_admin = ? WHERE id = ?",
                         (new_username, hashed_password, is_admin, user_id))
            else:
                # Update without changing password
                c.execute("UPDATE users SET username = ?, is_admin = ? WHERE id = ?",
                         (new_username, is_admin, user_id))
            
            conn.commit()
            flash('تم تحديث بيانات المستخدم بنجاح', 'success')
            conn.close()
            return redirect(url_for('admin'))
            
        except sqlite3.IntegrityError:
            flash('خطأ في تحديث البيانات', 'error')
            conn.close()
    
    conn.close()
    return render_template('edit_user.html', user=user)

@app.route('/manage_fields')
def manage_fields():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM dynamic_fields ORDER BY field_order, field_name")
    fields = c.fetchall()
    conn.close()
    
    return render_template('manage_fields.html', fields=fields)

@app.route('/add_field', methods=['GET', 'POST'])
def add_field():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        field_name = request.form['field_name'].strip().lower().replace(' ', '_')
        field_label = request.form['field_label'].strip()
        field_type = request.form['field_type']
        field_options = request.form.get('field_options', '').strip()
        is_required = 1 if 'is_required' in request.form else 0
        validation_rules = request.form.get('validation_rules', '').strip()
        field_order = int(request.form.get('field_order', 0))
        
        # Validation
        if len(field_name) < 2:
            flash('اسم الحقل يجب أن يكون حرفين على الأقل', 'error')
            return render_template('add_field.html')
        
        if len(field_label) < 2:
            flash('تسمية الحقل يجب أن تكون حرفين على الأقل', 'error')
            return render_template('add_field.html')
        
        # Check for reserved field names
        reserved_names = ['id', 'full_name', 'national_id', 'phone', 'status', 'family_members', 'address', 'notes', 'added_by', 'created_at']
        if field_name in reserved_names:
            flash(f'اسم الحقل "{field_name}" محجوز، يرجى اختيار اسم آخر', 'error')
            return render_template('add_field.html')
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        try:
            c.execute('''INSERT INTO dynamic_fields 
                        (field_name, field_label, field_type, field_options, is_required, validation_rules, field_order)
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (field_name, field_label, field_type, field_options, is_required, validation_rules, field_order))
            conn.commit()
            flash('تم إضافة الحقل بنجاح', 'success')
            conn.close()
            return redirect(url_for('manage_fields'))
            
        except sqlite3.IntegrityError:
            flash('اسم الحقل موجود مسبقاً', 'error')
            conn.close()
    
    return render_template('add_field.html')

@app.route('/edit_field/<int:field_id>', methods=['GET', 'POST'])
def edit_field(field_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    c.execute("SELECT * FROM dynamic_fields WHERE id = ?", (field_id,))
    field = c.fetchone()
    
    if not field:
        flash('الحقل غير موجود', 'error')
        conn.close()
        return redirect(url_for('manage_fields'))
    
    if request.method == 'POST':
        field_name = request.form['field_name'].strip().lower().replace(' ', '_')
        field_label = request.form['field_label'].strip()
        field_type = request.form['field_type']
        field_options = request.form.get('field_options', '').strip()
        is_required = 1 if 'is_required' in request.form else 0
        validation_rules = request.form.get('validation_rules', '').strip()
        field_order = int(request.form.get('field_order', 0))
        is_active = 1 if 'is_active' in request.form else 0
        
        # Check if field name exists for another field
        c.execute("SELECT id FROM dynamic_fields WHERE field_name = ? AND id != ?", (field_name, field_id))
        if c.fetchone():
            flash('اسم الحقل موجود مسبقاً لحقل آخر', 'error')
            conn.close()
            return render_template('edit_field.html', field=field)
        
        try:
            c.execute('''UPDATE dynamic_fields SET 
                        field_name = ?, field_label = ?, field_type = ?, field_options = ?,
                        is_required = ?, validation_rules = ?, field_order = ?, is_active = ?
                        WHERE id = ?''',
                     (field_name, field_label, field_type, field_options, is_required, 
                      validation_rules, field_order, is_active, field_id))
            conn.commit()
            flash('تم تحديث الحقل بنجاح', 'success')
            conn.close()
            return redirect(url_for('manage_fields'))
            
        except Exception as e:
            flash('خطأ في تحديث الحقل', 'error')
            conn.close()
    
    conn.close()
    return render_template('edit_field.html', field=field)

@app.route('/delete_field/<int:field_id>', methods=['DELETE'])
def delete_field(field_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Delete field values first
    c.execute("DELETE FROM dynamic_field_values WHERE field_id = ?", (field_id,))
    # Delete the field
    c.execute("DELETE FROM dynamic_fields WHERE id = ?", (field_id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

def get_dynamic_fields():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM dynamic_fields WHERE is_active = 1 ORDER BY field_order, field_label")
    fields = c.fetchall()
    conn.close()
    return fields

def get_citizen_dynamic_values(citizen_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("""SELECT df.field_name, dfv.field_value 
                FROM dynamic_fields df 
                LEFT JOIN dynamic_field_values dfv ON df.id = dfv.field_id AND dfv.citizen_id = ?
                WHERE df.is_active = 1
                ORDER BY df.field_order, df.field_label""", (citizen_id,))
    values = c.fetchall()
    conn.close()
    return dict(values)

def save_dynamic_field_values(citizen_id, form_data):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get all dynamic fields
    c.execute("SELECT id, field_name FROM dynamic_fields WHERE is_active = 1")
    fields = c.fetchall()
    
    for field_id, field_name in fields:
        field_value = form_data.get(f'dynamic_{field_name}', '')
        
        # Check if value exists
        c.execute("SELECT id FROM dynamic_field_values WHERE citizen_id = ? AND field_id = ?", 
                 (citizen_id, field_id))
        existing = c.fetchone()
        
        if existing:
            # Update existing value
            c.execute("UPDATE dynamic_field_values SET field_value = ? WHERE citizen_id = ? AND field_id = ?",
                     (field_value, citizen_id, field_id))
        else:
            # Insert new value
            c.execute("INSERT INTO dynamic_field_values (citizen_id, field_id, field_value) VALUES (?, ?, ?)",
                     (citizen_id, field_id, field_value))
    
    conn.commit()
    conn.close()

@app.route('/export_pdf')
def export_pdf():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM citizens ORDER BY created_at DESC")
    citizens = c.fetchall()
    conn.close()
    
    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=A4)
    
    # Create table data
    data = [['الرقم', 'الاسم', 'الرقم الوطني', 'الجوال', 'الحالة', 'أفراد الأسرة']]
    for citizen in citizens:
        data.append([
            str(citizen[0]),
            citizen[1][:20],
            citizen[2],
            citizen[3],
            citizen[4],
            str(citizen[5])
        ])
    
    # Create table
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    doc.build([table])
    output.seek(0)
    
    return send_file(
        output,
        as_attachment=True,
        download_name=f'citizens_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf',
        mimetype='application/pdf'
    )

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
