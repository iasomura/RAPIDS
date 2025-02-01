\set QUIET 1
\timing off
\pset footer off
\pset format unaligned
\pset fieldsep ','

\o '/home/asomura/waseda/nextstep/RAPIDS/reports/database_analysis/normal_sites/unknown_registrar_structured_analysis.csv'

-- ヘッダー行
COPY (
    SELECT 'domain,last_update,certificate_issuer,ip_address,ip_organization,extracted_registrar,registration_date,expiry_date'
) TO STDOUT;

-- データの出力（WHOISから情報を抽出）
COPY (
    SELECT 
        domain,
        TO_CHAR(last_update, 'YYYY-MM-DD HH24:MI:SS'),
        https_certificate_issuer,
        ip_address,
        ip_organization,
        CASE 
            WHEN whois_domain LIKE '%Registrar:%' THEN 
                SUBSTRING(whois_domain FROM 'Registrar:\s+([^\n]+)') 
            WHEN whois_domain LIKE '%등록대행자:%' THEN
                SUBSTRING(whois_domain FROM '등록대행자:\s+([^\n]+)')
            ELSE NULL 
        END as extracted_registrar,
        CASE 
            WHEN whois_domain LIKE '%Registered on:%' THEN 
                SUBSTRING(whois_domain FROM 'Registered on:\s+([^\n]+)')
            WHEN whois_domain LIKE '%Registered Date:%' THEN
                SUBSTRING(whois_domain FROM 'Registered Date:\s+([^\n]+)')
            WHEN whois_domain LIKE '%등록일:%' THEN
                SUBSTRING(whois_domain FROM '등록일:\s+([^\n]+)')
            ELSE NULL 
        END as registration_date,
        CASE 
            WHEN whois_domain LIKE '%Expiry date:%' THEN 
                SUBSTRING(whois_domain FROM 'Expiry date:\s+([^\n]+)')
            WHEN whois_domain LIKE '%Expiration Date:%' THEN
                SUBSTRING(whois_domain FROM 'Expiration Date:\s+([^\n]+)')
            WHEN whois_domain LIKE '%사용 종료일:%' THEN
                SUBSTRING(whois_domain FROM '사용 종료일:\s+([^\n]+)')
            ELSE NULL 
        END as expiry_date
    FROM website_data 
    WHERE status = 7 
    AND (domain_registrar IS NULL OR domain_registrar = '')
    ORDER BY last_update DESC
    LIMIT 1000
) TO STDOUT WITH CSV;

\o
