--
-- PostgreSQL database dump
--

-- Dumped from database version 14.11 (Ubuntu 14.11-0ubuntu0.22.04.1)
-- Dumped by pg_dump version 14.11 (Ubuntu 14.11-0ubuntu0.22.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: role; Type: TABLE; Schema: public; Owner: haus
--

CREATE TABLE public.role (
    id integer NOT NULL,
    name character varying(80)
);


ALTER TABLE public.role OWNER TO haus;

--
-- Name: role_id_seq; Type: SEQUENCE; Schema: public; Owner: haus
--

CREATE SEQUENCE public.role_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.role_id_seq OWNER TO haus;

--
-- Name: role_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: haus
--

ALTER SEQUENCE public.role_id_seq OWNED BY public.role.id;


--
-- Name: roles_users; Type: TABLE; Schema: public; Owner: haus
--

CREATE TABLE public.roles_users (
    user_id integer,
    role_id integer
);


ALTER TABLE public.roles_users OWNER TO haus;

--
-- Name: user; Type: TABLE; Schema: public; Owner: haus
--

CREATE TABLE public."user" (
    id integer NOT NULL,
    email character varying,
    password character varying(255) DEFAULT ''::character varying NOT NULL,
    active boolean
);


ALTER TABLE public."user" OWNER TO haus;

--
-- Name: user_id_seq; Type: SEQUENCE; Schema: public; Owner: haus
--

CREATE SEQUENCE public.user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.user_id_seq OWNER TO haus;

--
-- Name: user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: haus
--

ALTER SEQUENCE public.user_id_seq OWNED BY public."user".id;


--
-- Name: role id; Type: DEFAULT; Schema: public; Owner: haus
--

ALTER TABLE ONLY public.role ALTER COLUMN id SET DEFAULT nextval('public.role_id_seq'::regclass);


--
-- Name: user id; Type: DEFAULT; Schema: public; Owner: haus
--

ALTER TABLE ONLY public."user" ALTER COLUMN id SET DEFAULT nextval('public.user_id_seq'::regclass);


--
-- Data for Name: role; Type: TABLE DATA; Schema: public; Owner: haus
--

COPY public.role (id, name) FROM stdin;
1	Admin
2	Teacher
3	Staff
4	Student
\.


--
-- Data for Name: roles_users; Type: TABLE DATA; Schema: public; Owner: haus
--

COPY public.roles_users (user_id, role_id) FROM stdin;
1	4
2	2
3	3
4	1
5	4
\.


--
-- Data for Name: user; Type: TABLE DATA; Schema: public; Owner: haus
--

COPY public."user" (id, email, password, active) FROM stdin;
1	topstudent@gmail.com	abc123	t
2	bestteacher@gmail.com	abc123	t
3	madscot@gmail.com	abc123	t
4	eviladmin@gmail.com	abc123	t
5	theflash@gmail.com	abc123	t
\.


--
-- Name: role_id_seq; Type: SEQUENCE SET; Schema: public; Owner: haus
--

SELECT pg_catalog.setval('public.role_id_seq', 1, false);


--
-- Name: user_id_seq; Type: SEQUENCE SET; Schema: public; Owner: haus
--

SELECT pg_catalog.setval('public.user_id_seq', 5, true);


--
-- Name: role role_name_key; Type: CONSTRAINT; Schema: public; Owner: haus
--

ALTER TABLE ONLY public.role
    ADD CONSTRAINT role_name_key UNIQUE (name);


--
-- Name: role role_pkey; Type: CONSTRAINT; Schema: public; Owner: haus
--

ALTER TABLE ONLY public.role
    ADD CONSTRAINT role_pkey PRIMARY KEY (id);


--
-- Name: user user_email_key; Type: CONSTRAINT; Schema: public; Owner: haus
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT user_email_key UNIQUE (email);


--
-- Name: user user_pkey; Type: CONSTRAINT; Schema: public; Owner: haus
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT user_pkey PRIMARY KEY (id);


--
-- Name: roles_users roles_users_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: haus
--

ALTER TABLE ONLY public.roles_users
    ADD CONSTRAINT roles_users_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.role(id);


--
-- Name: roles_users roles_users_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: haus
--

ALTER TABLE ONLY public.roles_users
    ADD CONSTRAINT roles_users_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- PostgreSQL database dump complete
--

