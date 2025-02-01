\set QUIET 1
\timing off
\pset footer off
\pset format unaligned
\pset fieldsep ','

\o '/home/asomura/waseda/nextstep/RAPIDS/reports/database_analysis/normal_sites/unknown_registrar_analysis.csv'

-- ヘッダー行の出力
COPY (
    SELECT 'domain,domain_status,last_update,https_certificate_issuer,https_certificate_domain,ip_address,ip_organization,whois_domain'
) TO STDOUT;

-- データの出力
COPY (
    SELECT 
        domain,
        REPLACE(COALESCE(domain_status, ''), E'\n', ' '),
        COALESCE(TO_CHAR(last_update, 'YYYY-MM-DD HH24:MI:SS'), ''),
        REPLACE(COALESCE(https_certificate_issuer, ''), E'\n', ' '),
        REPLACE(COALESCE(https_certificate_domain, ''), E'\n', ' '),
        COALESCE(ip_address, ''),
        REPLACE(COALESCE(ip_organization, ''), E'\n', ' '),
        REPLACE(REPLACE(COALESCE(whois_domain, ''), E'\n', ' '), ',', ';')
    FROM website_data 
    WHERE status = 7 
    AND (domain_registrar IS NULL OR domain_registrar = '')
    ORDER BY last_update DESC
    LIMIT 1000
) TO STDOUT WITH CSV;

\o
