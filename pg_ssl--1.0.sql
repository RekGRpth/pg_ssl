-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_ssl" to load this file. \quit

CREATE OR REPLACE FUNCTION sign(cert text, data text) RETURNS text AS 'MODULE_PATHNAME', 'sign' LANGUAGE 'c';
