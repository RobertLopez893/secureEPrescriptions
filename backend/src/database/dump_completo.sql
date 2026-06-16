--
-- PostgreSQL database dump
--

\restrict meoPeqKrWuMoBitEakmqQvYv9KYdF5lFIdbGOcpWlMDggmFEnYNlTw1D19TrSCY

-- Dumped from database version 15.18
-- Dumped by pg_dump version 15.18

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

--
-- Data for Name: administradores; Type: TABLE DATA; Schema: public; Owner: admin
--

INSERT INTO public.administradores (id_admin, nombre, correo, contrasena, activo, creado_en) VALUES (1, 'Admin Demo', 'admin@rxpro.demo', '$2b$12$MlKVCZzlxdoWG6vJZ1sWQeKxCIquls.eCStnRZbG5Pf.GpRxV7yZm', true, '2026-05-20 22:17:04.457247');


--
-- Data for Name: clinicas; Type: TABLE DATA; Schema: public; Owner: admin
--

INSERT INTO public.clinicas (id_clinica, nombre, clues, calle, colonia, municipio, estado, cp, tipo) VALUES (1, 'Clínica Demo RxFlow', 'DEMO0000001', 'Av. Ficticia 123', 'Centro', 'Ciudad Demo', 'CDMX', '01000', 'Centro Medico');
INSERT INTO public.clinicas (id_clinica, nombre, clues, calle, colonia, municipio, estado, cp, tipo) VALUES (2, 'IMSS', '6767', 'Vicente Guerrero', 'Ampliación Tulpetlac', 'Ecatepec', 'Estado de México', '55400', 'Hospital');


--
-- Data for Name: roles; Type: TABLE DATA; Schema: public; Owner: admin
--

INSERT INTO public.roles (id_rol, nombre) VALUES (1, 'Medico');
INSERT INTO public.roles (id_rol, nombre) VALUES (2, 'Paciente');
INSERT INTO public.roles (id_rol, nombre) VALUES (3, 'Farmaceutico');


--
-- Data for Name: usuarios; Type: TABLE DATA; Schema: public; Owner: admin
--

INSERT INTO public.usuarios (id_usuario, id_rol, id_clinica, nombre, paterno, materno, correo, contrasena, activo, creado_en) VALUES (1, 1, 1, 'Demo', 'Médico', NULL, 'doctor@rxpro.demo', '$2b$12$67f1zkQCE1bYgIkybzZBzuq.7ynauhYh7xegklvMricCTruVhiNYW', true, '2026-05-20 22:17:04.210889');
INSERT INTO public.usuarios (id_usuario, id_rol, id_clinica, nombre, paterno, materno, correo, contrasena, activo, creado_en) VALUES (2, 2, 1, 'Demo', 'Paciente', NULL, 'paciente@rxpro.demo', '$2b$12$67f1zkQCE1bYgIkybzZBzuq.7ynauhYh7xegklvMricCTruVhiNYW', true, '2026-05-20 22:17:04.211103');
INSERT INTO public.usuarios (id_usuario, id_rol, id_clinica, nombre, paterno, materno, correo, contrasena, activo, creado_en) VALUES (3, 3, 1, 'Demo', 'Farmacéutico', NULL, 'farma@rxpro.demo', '$2b$12$67f1zkQCE1bYgIkybzZBzuq.7ynauhYh7xegklvMricCTruVhiNYW', true, '2026-05-20 22:17:04.211439');
INSERT INTO public.usuarios (id_usuario, id_rol, id_clinica, nombre, paterno, materno, correo, contrasena, activo, creado_en) VALUES (4, 2, 1, 'Paciente1', 'Demo', NULL, 'paciente1@rxpro.demo', '$2b$12$67f1zkQCE1bYgIkybzZBzuq.7ynauhYh7xegklvMricCTruVhiNYW', true, '2026-05-20 22:17:04.471486');
INSERT INTO public.usuarios (id_usuario, id_rol, id_clinica, nombre, paterno, materno, correo, contrasena, activo, creado_en) VALUES (5, 2, 1, 'Paciente2', 'Demo', NULL, 'paciente2@rxpro.demo', '$2b$12$67f1zkQCE1bYgIkybzZBzuq.7ynauhYh7xegklvMricCTruVhiNYW', true, '2026-05-20 22:17:04.487032');
INSERT INTO public.usuarios (id_usuario, id_rol, id_clinica, nombre, paterno, materno, correo, contrasena, activo, creado_en) VALUES (6, 2, 1, 'Paciente3', 'Demo', NULL, 'paciente3@rxpro.demo', '$2b$12$67f1zkQCE1bYgIkybzZBzuq.7ynauhYh7xegklvMricCTruVhiNYW', true, '2026-05-20 22:17:04.502358');
INSERT INTO public.usuarios (id_usuario, id_rol, id_clinica, nombre, paterno, materno, correo, contrasena, activo, creado_en) VALUES (7, 2, 1, 'Paciente4', 'Demo', NULL, 'paciente4@rxpro.demo', '$2b$12$67f1zkQCE1bYgIkybzZBzuq.7ynauhYh7xegklvMricCTruVhiNYW', true, '2026-05-20 22:17:04.51601');
INSERT INTO public.usuarios (id_usuario, id_rol, id_clinica, nombre, paterno, materno, correo, contrasena, activo, creado_en) VALUES (8, 2, 1, 'Paciente5', 'Demo', NULL, 'paciente5@rxpro.demo', '$2b$12$67f1zkQCE1bYgIkybzZBzuq.7ynauhYh7xegklvMricCTruVhiNYW', true, '2026-05-20 22:17:04.528563');
INSERT INTO public.usuarios (id_usuario, id_rol, id_clinica, nombre, paterno, materno, correo, contrasena, activo, creado_en) VALUES (9, 1, 1, 'Doctor1', 'Demo', NULL, 'doctor1@rxpro.demo', '$2b$12$67f1zkQCE1bYgIkybzZBzuq.7ynauhYh7xegklvMricCTruVhiNYW', true, '2026-05-20 22:17:04.542294');
INSERT INTO public.usuarios (id_usuario, id_rol, id_clinica, nombre, paterno, materno, correo, contrasena, activo, creado_en) VALUES (10, 1, 1, 'Doctor2', 'Demo', NULL, 'doctor2@rxpro.demo', '$2b$12$67f1zkQCE1bYgIkybzZBzuq.7ynauhYh7xegklvMricCTruVhiNYW', true, '2026-05-20 22:17:04.559331');
INSERT INTO public.usuarios (id_usuario, id_rol, id_clinica, nombre, paterno, materno, correo, contrasena, activo, creado_en) VALUES (11, 1, 1, 'Doctor3', 'Demo', NULL, 'doctor3@rxpro.demo', '$2b$12$67f1zkQCE1bYgIkybzZBzuq.7ynauhYh7xegklvMricCTruVhiNYW', true, '2026-05-20 22:17:04.582731');
INSERT INTO public.usuarios (id_usuario, id_rol, id_clinica, nombre, paterno, materno, correo, contrasena, activo, creado_en) VALUES (12, 2, 1, 'Roberto', 'López', 'Reyes', 'lopez.reyes.roberto.m@gmail.com', '$2b$12$jYfoNggm9iKro8nJvRe.oe7n4UVOL83RZbCHcSXQMpvtb0NmyPNb.', true, '2026-05-20 23:19:24.999595');
INSERT INTO public.usuarios (id_usuario, id_rol, id_clinica, nombre, paterno, materno, correo, contrasena, activo, creado_en) VALUES (13, 1, 1, 'Hatziry', 'Vitales', 'Herrera', 'hvitalesh1900@alumno.ipn.mx', '$2b$12$40bJEka/fFyAw4x0UwpsdOd4R7n2EdhUFi2/zcltOzvXt3EH3WtZS', true, '2026-05-20 23:42:33.154633');
INSERT INTO public.usuarios (id_usuario, id_rol, id_clinica, nombre, paterno, materno, correo, contrasena, activo, creado_en) VALUES (14, 1, 1, 'Eduardo', 'Alonso', 'Sánchez', 'contacto@eddndev.com', '$2b$12$av5cSZeiQ1X7qHMSImCw6.V.OE5K708Qp.Jp4n8XGTlPnhT5BMpuy', true, '2026-05-20 23:43:39.053029');
INSERT INTO public.usuarios (id_usuario, id_rol, id_clinica, nombre, paterno, materno, correo, contrasena, activo, creado_en) VALUES (15, 1, 2, 'Emiliano', 'Torres', 'Larios', 'atorresl1900@alumno.ipn.mx', '$2b$12$/WPDAz.lx8oyo770CKn5g.L42rKhY9sa4ctml7HIU0nfUSovFKKOq', true, '2026-05-20 23:45:33.443028');
INSERT INTO public.usuarios (id_usuario, id_rol, id_clinica, nombre, paterno, materno, correo, contrasena, activo, creado_en) VALUES (16, 3, 2, 'Ajelandro', 'Hernández', 'Zarzamora', 'hernandezzz1902@alumno.ipn.mx', '$2b$12$UN72TnmnVivKc6gwwffpHupAyHXnKpkFmKbHtzt9.mm0mm9EJrwp6', true, '2026-05-20 23:46:39.135474');
INSERT INTO public.usuarios (id_usuario, id_rol, id_clinica, nombre, paterno, materno, correo, contrasena, activo, creado_en) VALUES (17, 3, 1, 'Brandon', 'Velázquez', 'Beltrán', 'brandon@hotmail.com', '$2b$12$.Kadvi60F/XjtHlbGsCh4OpXMhy0gD14WAcvD84T8t1njoXMHETvC', true, '2026-05-20 23:47:54.095597');
INSERT INTO public.usuarios (id_usuario, id_rol, id_clinica, nombre, paterno, materno, correo, contrasena, activo, creado_en) VALUES (18, 2, 2, 'Alfonso Enrique', 'Escobar', 'Garmendia', 'alfonrique@gmail.com', '$2b$12$acDHnKkIMccLomQBsJ2Pi.5v.mIr58vXZgH1GaWIwHnFi7WwBael2', true, '2026-05-20 23:51:15.290942');


--
-- Data for Name: farmaceuticos; Type: TABLE DATA; Schema: public; Owner: admin
--

INSERT INTO public.farmaceuticos (id_usuario, licencia, turno) VALUES (3, 'DEMO-FARM-0001', 'Matutino');
INSERT INTO public.farmaceuticos (id_usuario, licencia, turno) VALUES (16, '44446767', 'Nocturno');
INSERT INTO public.farmaceuticos (id_usuario, licencia, turno) VALUES (17, '2480', 'Vespertino');


--
-- Data for Name: llaves; Type: TABLE DATA; Schema: public; Owner: admin
--

INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (1, 1, '047193ac9c097ea3b214ca7d8a29b562c277a92803adaa30a8babe761c4ee53bc611e2c13f4c17038dda2345b67c503c221605e8f887d464d48525a0c89ddbf96e', true, '2026-05-20 22:17:04.236255', 'recetas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (2, 2, '0420a09faa2eb7ed6145d868f57ac9d17c14428d0a06d88ee40c13ec52f61ce640c1dcc2f1b6c31515fe649857083a1efc25b609c2b57d172f52a6d640ff7d027e', true, '2026-05-20 22:17:04.236478', 'recetas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (3, 3, '04465b811600d81766f0cb446d9c0b949546b0bb9ba6aa23726d5080cff52f5ed6d80416a73fbb38f2b4effe7d4190146bac831f24c6282deaeb1f6fc50a169aac', true, '2026-05-20 22:17:04.236612', 'recetas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (4, 1, '040223f8a2e516c1a6e03eaced04ca265eab328ef9c4044c94eb421ce6fd795dde73939704a097c3e76bcd62f6ec9c06ea68374939a1f9fe82ebf0fcf62dbe0fe3', true, '2026-05-20 22:17:04.236728', 'firmas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (5, 2, '043353e5e851f4d77748992093c00700ef36b203bd4b68455cf3832fff1b579e397556c7738c66da7529770402d16bfe8c8f90ee34ce56d959a6b8e90b5a575532', true, '2026-05-20 22:17:04.236807', 'firmas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (6, 3, '04413f2accae956247d714208c8146801234d7225dd8b322a96a380510844de11660210d6d322e0c56729ee89bbdca523f72c05bf007300a4367727a546d557717', true, '2026-05-20 22:17:04.236873', 'firmas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (7, 4, '045452da4bc885063b7e8a72bb7051a6f7f3cbc8137f1fcdc00937b9bb395bd033de8a4fb666397494849efc01c5d47c60ef2dc33ee37c86e0608eb260d568f29d', true, '2026-05-20 22:17:04.483714', 'recetas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (8, 4, '046b8476672e6dbe22217aa8cd78d56ac9ac785acb7b9c8939ff2d6116de810aac47fe96a8e05a268fad785e976cf3ce0743089cdd5ceda827c828aab5566398f0', true, '2026-05-20 22:17:04.483832', 'firmas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (9, 5, '04da704a8b04cf61157684bf93802b59a8cfcbe5ac49497d57d2726a2897909f8beb359c57285bbb8b6e8d7017913ee8a76586b8d2e0a5330e34eb9a59c9b95751', true, '2026-05-20 22:17:04.498457', 'recetas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (10, 5, '049d5c150ab56fa105dfccdd88454d36485dd6f1ef4025dbd48dc11e4cc36056ade7c7aba3faa8f8edb239d1ed00627b9b9a5502ad0722b3be98f7905512b37083', true, '2026-05-20 22:17:04.498585', 'firmas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (11, 6, '0495419540869c194d8c722b302f74cf9ac7c0a48f1f91973db18af980c38735a82c894a6cce951439e6424aeb15778b4807a9b89ca49cce16cbc9607b0570c03e', true, '2026-05-20 22:17:04.512338', 'recetas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (12, 6, '0440a13bd08032da6629b0bd800a0561801123f76ee6391b354f1cf1fc9b51ec3d47dcb60cb4b96bc48cd15d33ebc09645a8966dc81f0b8a4f46198e4332b1ee16', true, '2026-05-20 22:17:04.51246', 'firmas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (13, 7, '04662d4ed988bada355a640eefe4c07048c3e2017f9de72fd3de4926d4a71deb3d39f06ee7c6efcf5ea6a05507213ae5e77c68b2029645053cb8c1bcd40925968d', true, '2026-05-20 22:17:04.525035', 'recetas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (14, 7, '04ec387e647b99e162d6462908ca0707c866c18431349227e6184eb32c4593208f639e80b8ac5657ec30d020bee0ea9eced47278d8a8b670630327ad7d51b589fc', true, '2026-05-20 22:17:04.525169', 'firmas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (15, 8, '04b7c433ee3363c204aeae63a5b99a6ce9750f962fa876f5b3b1f05eacd3dfc0ef2e9ad107b359ca3420dc371d7086913abcdbad61777922391bb9abcc9bab38ab', true, '2026-05-20 22:17:04.537971', 'recetas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (16, 8, '04d0f1125e9b34e4a08397143fe0721a71763e635e233a3a5ef47a18f1c0f1cdf50c0cd14317bd98e7b875cb8ed14f20688f60aac402bf9806acc323f04025b0f0', true, '2026-05-20 22:17:04.538117', 'firmas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (17, 9, '04f12f8b3050908a48e1ea9b60e93176e7b056fef59aa24143c90603f23287646a05da433aefa9d207ab21f7f63188ecb51505fd8432e4079eebe164ded80b35b6', true, '2026-05-20 22:17:04.555413', 'recetas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (18, 9, '040c8d838155f6ca8a0c179c698155d725b4d5e9f36f3e0fd0694899094bf049446e79edfd2aa7b5f9b4bfa50d7fe11b75d73d82fa8d77da8481ae26c41aecf3fa', true, '2026-05-20 22:17:04.555526', 'firmas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (19, 10, '0426e693f47f123d4f41afcb8adc57eb338add9f1c5972e482d31cba7be09bc1e26f1a70fe8171b865c289a1d75aad9aee410cfe25ce2e85c38b0460998477a716', true, '2026-05-20 22:17:04.576224', 'recetas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (20, 10, '0417466d134972b16d963b4170cb8de7ed472e27cfd54d72b40f74116cdf7a371379467a901a122671e1bec9cbe5f2326cc3fd2d8d0d3e34a770067338fbb82a6b', true, '2026-05-20 22:17:04.576369', 'firmas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (21, 11, '04bbb16be618c89cb4135c47b341416f1e9ff1788f1d24c1a68ec050e01c55a8b4174430a70238d2616d9240f9f22adfa607182ee3e06a6923d5adf23e3bbd5150', true, '2026-05-20 22:17:04.601043', 'recetas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (22, 11, '044e6517165547f88ec4a4344a830af3cac3720bcc3b2148135dbea1e4886be4efeaf48f0e4889ea89334342f11ba871e4635a1619c3bac378427d3ae86b76b4eb', true, '2026-05-20 22:17:04.601252', 'firmas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (23, 12, '04fdae1ffe35875928f98a802a3f3c11eaa8e27c2d771dc6473d50bd927aece080a61d0e7facd2f022ab2ea739c96ad16da4f4e37c921697245b7ef19ebff5ce02', true, '2026-05-20 23:19:25.030591', 'firmas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (24, 12, '04f4940f2b6c74463fed8edea5449e5ce7c33cc7ca56a03c08eed8582da02d4fd48d89c809b26c97bc9d74897fead4fbd6a073fa8d1f5f46bf53f73ea326cc9f95', true, '2026-05-20 23:19:25.047397', 'recetas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (25, 13, '04aaf0c7ad3845df3e967bfc29d7a6deb1c8ea288f123f38a3cbddf06b31769b752127927ecea19ca7a1b4f33a98afb6bebf21d9ac504c9f2cf26bccfd32f9fcc7', true, '2026-05-20 23:42:33.176014', 'firmas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (26, 13, '0477a32995be5870644154d3cb9017816df5dbf7210ec68fbe01002b99f8d5853818285b7af04bc01860edf08a52e005e20d2475975ca7407f3b53e0de9bf4ad4f', true, '2026-05-20 23:42:33.189344', 'recetas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (27, 14, '0464f739d0ff7824c7a7e1a3225d5fad36e2f69e5ee543ebff34a6faf6e1d71f2c95c9fd470b01e47b46bdf91e614d4cb1105ba4d1597bcf98b0afaa9b603dc8e5', true, '2026-05-20 23:43:39.075609', 'firmas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (28, 14, '04c237b58ba242a1ed681e20fefb6156aca87d55668a10895d66dc8a795bd9cf0e32182ab82ae16c87452be1bab5e04bf7b8a9b584216ade510541b950dea2545a', true, '2026-05-20 23:43:39.090178', 'recetas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (29, 15, '04be1286eed508b7a756caf50e80aa9580627627709e64d6e9e265e7d333c02ab3378ecb525ec266954a4b43cbd5815f63968cfd1d3eb3f682f740045af32966fa', true, '2026-05-20 23:45:33.461398', 'firmas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (30, 15, '0482889a61a088d06f44507b3ac3cd8ddb21cbc0c868f211a5d5c22575c8f90b9f8891bf6a8b85c382cd87fea25937e06c11985df5ec3fc7f2a2aa1c5db2570abb', true, '2026-05-20 23:45:33.472627', 'recetas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (31, 16, '0425372402db3b8f8656c5aee99e98ed452ab7e0ed3110b88b60bfe18eb201b48173a2978bc4389eec529363532721f7ef6bb757f2e7003baa60e5330eafc46acd', true, '2026-05-20 23:46:39.154141', 'firmas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (32, 16, '04ae13b94f71540071b305d759509aba3dc4401b3ce187c6e30d79e55e4d6f768d665a46d7255c10af28e21013ec91d4ae9bb504b8a69c4823cd57d85ed5e048da', true, '2026-05-20 23:46:39.169397', 'recetas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (33, 17, '04f8a4f0819502a511d8b4033319c764c864abfddac889a18d32ac1863df3a961c59d8825f8aeff34908feb624c9d8c68475a7fd7a3b9d6eff9f5bebe1e967da44', true, '2026-05-20 23:47:54.360732', 'firmas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (34, 17, '044f6e68f97e1247f4360d929501a74965e856ab5423b89fc71eaf8b46e0a43c66d42da05b463a523ef3abdd1637dfdf65455d799f3218e0a42ff90c11e19a1af1', true, '2026-05-20 23:47:54.585847', 'recetas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (35, 18, '04580927c4a61e74f3f33ca29106c289b9be85b930778e024e06049a7652f77ae55c92c67b7f310580f0091fab9a19e2fb12dc8017e66f6f78af016ed2b0580b77', true, '2026-05-20 23:51:15.310544', 'firmas');
INSERT INTO public.llaves (id_llave, id_usuario, llave_publica, activo, creado_en, responsabilidad) VALUES (36, 18, '04df9720f3ce6ab488fdb78d0a3dc0d10f41bcb859b4c3e7ff35eba73b028709b09f639aba281d2c1301f779d8be0666db993beb7fd1fe29581f87d0996cdc5ae8', true, '2026-05-20 23:51:15.323513', 'recetas');


--
-- Data for Name: medicos; Type: TABLE DATA; Schema: public; Owner: admin
--

INSERT INTO public.medicos (id_usuario, cedula, especialidad, universidad) VALUES (1, 'DEMO-MED-0001', 'General', 'Universidad Demo');
INSERT INTO public.medicos (id_usuario, cedula, especialidad, universidad) VALUES (9, 'DEMO-MED-1001', 'General', 'Universidad Demo');
INSERT INTO public.medicos (id_usuario, cedula, especialidad, universidad) VALUES (10, 'DEMO-MED-1002', 'General', 'Universidad Demo');
INSERT INTO public.medicos (id_usuario, cedula, especialidad, universidad) VALUES (11, 'DEMO-MED-1003', 'General', 'Universidad Demo');
INSERT INTO public.medicos (id_usuario, cedula, especialidad, universidad) VALUES (13, '12345678', 'Cardiología', 'ESCOM IPN');
INSERT INTO public.medicos (id_usuario, cedula, especialidad, universidad) VALUES (14, '87654321', 'Dermatología', 'ESCOM IPN');
INSERT INTO public.medicos (id_usuario, cedula, especialidad, universidad) VALUES (15, '12345670', 'Neumología', 'ESCOM IPN');


--
-- Data for Name: pacientes; Type: TABLE DATA; Schema: public; Owner: admin
--

INSERT INTO public.pacientes (id_usuario, curp, nacimiento, sexo, tel_emergencia) VALUES (2, 'DEMO000101HDFXXX01', '2000-01-01', 'O', '5555555555');
INSERT INTO public.pacientes (id_usuario, curp, nacimiento, sexo, tel_emergencia) VALUES (4, 'PAC01000101HDFXXX01', '2000-01-01', 'O', '5555555555');
INSERT INTO public.pacientes (id_usuario, curp, nacimiento, sexo, tel_emergencia) VALUES (5, 'PAC02000101HDFXXX02', '2000-01-01', 'O', '5555555555');
INSERT INTO public.pacientes (id_usuario, curp, nacimiento, sexo, tel_emergencia) VALUES (6, 'PAC03000101HDFXXX03', '2000-01-01', 'O', '5555555555');
INSERT INTO public.pacientes (id_usuario, curp, nacimiento, sexo, tel_emergencia) VALUES (7, 'PAC04000101HDFXXX04', '2000-01-01', 'O', '5555555555');
INSERT INTO public.pacientes (id_usuario, curp, nacimiento, sexo, tel_emergencia) VALUES (8, 'PAC05000101HDFXXX05', '2000-01-01', 'O', '5555555555');
INSERT INTO public.pacientes (id_usuario, curp, nacimiento, sexo, tel_emergencia) VALUES (12, 'LORR041023HMCPYBA3', '2004-10-23', 'M', '5560689360');
INSERT INTO public.pacientes (id_usuario, curp, nacimiento, sexo, tel_emergencia) VALUES (18, 'EOGA990120HDFSRL09', '1999-01-20', 'M', '5570788913');


--
-- Data for Name: recetas; Type: TABLE DATA; Schema: public; Owner: admin
--

INSERT INTO public.recetas (id_receta, folio, id_medico, id_paciente, id_farmaceutico, capsula_cifrada, nonce, accesos, estado, creada_en, expira_en) VALUES (1, 'rx-1-20260520172933', 1, 12, 3, '36f8c5540ab47c1e5dd18febf53b417bb18fb6c60a4f3544ebaae1d6b555a80a9f1c9d6d75f0e1dac1b324cc9542168fdd8f2006e0f16120da18b246b9def020cc063423335b99d70399a5840c40f57ef2797bf4e728e28dadba8307848cfdbc33c7fb8ca53d339e6347d33a502cb2eb2e38137ecaae8ae3d8e67c61f8a891645fa3519551c0d6b93ff40d3ad6e4d3981e174637c3cb39538654b1a641306ca76949545d8967b3c7653e4b6930db86afa8bd26a9f95500a96dea26a2a91ac51d0e9c8f99fdf4a36331c7006ba19daecb21732af0a7ba0f7509edb05eaaa6d85b6e1a0b45cc7bdaca25d314c8cf8e50964d3789508781ebcc200f638910ccb11c470f2b6f0660b294e2f627cfaedd8ca638b231076d80cd1a562b24cd9281ac311de7d38cb82f9ac0d3dbda7b91817ba63630bf5ffb8de3e3aa62ac4f655f7f4affbf82814f13d5e0b191d4abaac3a66d90dec503dee974dab4bac8921b2e124f3eb29d41b70d7edb7656764d12cb822b3640415e944674688a1a47b3a5341488a78dfeb1d214733d99ff504abccfa0c380fdf508365847777f15723beec13313048f5990dd24648b9a1c8b1684098bd2f853b5d5a7ecf9e8cc3c6b7895aa6cdcd5b13babbb52d16709e96706c8efe6df9518380921e6647963b584b30d8937fc3b02bac849375441b7e5344e6991752dc9ca989490f2ef1c66075a36b276', '9461d048da2ff9e1bbff021a', '[{"rol": "paciente", "wrappedKey": "b9846b389820e72962379961bed18c3a23777965ac4af8f74df1b106381c96a49c93bf32d18d457b", "ephemeral_pub_hex": "043f79ab47d335842177d2297023c7eaf43934f78488875f82368682cccb9bc099d5667f4dcd9f798822006058d604d8ccc4b2a1e8448fd46413ad37db1188285f"}, {"rol": "farmaceutico", "wrappedKey": "4948d677a66e834839364c48c8089c7e296dc5b04b267c43cc6817fbed2c9275a6416959a4cd8481", "ephemeral_pub_hex": "0446a44dcb422940117fcdfd9f0ac81499bc7824fc5d3dcc524a18933ddb1e0ed09b94be9600150215b62954164c7d3bd7562dfdfb10cdcaaef9c8213d392d03ab"}, {"rol": "doctor", "wrappedKey": "d9f59cab408ef7f1d657f2999a71200aa92f28fc763c204f77c931d96bdeb8fc49f87311c37a5e58", "ephemeral_pub_hex": "049c7d9eb2868c49817906fbe38fcde74fb22e1ff4f9184268d3750d856797bf4341472c915a83c9f934068bc42959ff6ae840a7b08c09f75694416bc0dc3e9936"}]', 'activa', '2026-05-20 00:00:00', '2026-06-19 23:29:33.598');
INSERT INTO public.recetas (id_receta, folio, id_medico, id_paciente, id_farmaceutico, capsula_cifrada, nonce, accesos, estado, creada_en, expira_en) VALUES (2, 'rx-15-20260520175612', 15, 12, 16, 'f33d5753b9d34383f009bcd39c9a2e26b55fbea2246a972a62fed1146abd509cbbd6947226f366d7845d13edc967bf822867cf957e1069d33cc72e849c4aa21815009b459d24fbf6dbaab785cad91b75858021f043f4b6f2c6ae23e06c86d63a7a9ebed62a593da6223ef8c24dc970c83649e59a500d6680edba1c68ced779928084a2da821b82c6800ac60a01327e5e2a12ac0ad1882c9ddf93db6d3c12db831cfffc392b9399bb3047e8dc682ee8a00fe8aed2370bc0444fcf4724c45b2c247da9a21e950cf98c1cf5aee686cbbdd3122d80bd893ecdf1b9a244127da0bdff5247111581a6c72613ae0a816a95bdf3c036b0c6690d2767a47b1669b13edc41b5b1293abe20c3226ba371c0117179e0c4f49d253a19faefbc614ddd7fdbc21ad90a567f551b260f71206db4d42c757293f14084b2c8f96f966a1e955448992b160c63a14fe22908604286011c754bbebf6feb26d0d446391e299637675712b725b12068b981a174bde50ed91d702e810a975d4478342e6b30d8377624df8dca84bd36d3498400fe1f481d98acea580203c8cff4bd0c57ce1a83dc6b9b2f3742f80d9388bea6af9d66957440daa247e9794083ccc377845604b00969794e036d72fa3594fc793b3d97a3d39ca3e69248a8403137ba08d51aa202584af8848f5ea829a49821a84b90b02ed7f497bb4c28fc8fbf35f1e3684e93aa56b1d58630a21801cc2d8cc04fa7639e8d11dbb19194a1feb2a5846a21fb20c5ca37d77e62e93d0b49d0bb0f884d1dc7e0d92c27e9bafd07e4f9c46f74dad736c615bc690e621d52ad5f450088b1542e12d38ec2a63dffa30b23b26dcb99b2f2f15df0dbc0fe788c566ca629f5c7d91e315f74ffa3752e5c1fdb8aad14a03094cc717f56da2df6c3b988', '6bdbeee30d8ac095d01ccb94', '[{"rol": "paciente", "wrappedKey": "13af9c814ffbb61da090ba8600ff76d2929f8d4c0e6dc77786e325152362c49afe4d281f74ab4717", "ephemeral_pub_hex": "04fa599bb908453169262573f696cb86242fd187a4dbcc4c9db2476cd260ae08209eb9fb5ce9f6f824ca02f8f7dc30b148903bb492cc3b7ed6d268b727aa088d7f"}, {"rol": "farmaceutico", "wrappedKey": "ed4c35cab76f385526eb0b02f69fe28d6f50b35d58c454ffbb4ce508b9075968f704f2823b11bed1", "ephemeral_pub_hex": "047d6d12467b3add37dd7bfb86bc7993efc3be2ae5e7dae82bd469204a84a1216a3762a4e7d84e25606c303dec3b2c71718a076c913a76498bab5e58f45b3967d4"}, {"rol": "doctor", "wrappedKey": "a2531dadf84a7d780171976a742c8c34d20fab6256001f78b91417991bc87b2c19ecfe654bebc9d4", "ephemeral_pub_hex": "044b8c8847a519d20313b14850b82a8a9295aea62554e3f77a90e28addab0e11f99c5a01fb91f8d3a1f196561c2974434b968402e74a2d524af49f4596502cb765"}]', 'activa', '2026-05-20 00:00:00', '2026-06-19 23:56:12.784');
INSERT INTO public.recetas (id_receta, folio, id_medico, id_paciente, id_farmaceutico, capsula_cifrada, nonce, accesos, estado, creada_en, expira_en) VALUES (3, 'rx-15-20260520175918', 15, 18, 16, 'b200f078b41ab9931ba3159168a249e138f0bdcd2753cd1c0259a440a1a66c439d67b7b3ebd64efdf8d5cfd9fd963782e422f05864deccc3d5dcba16ae48291c96e3b4771f2afeedfe18a9fc7b1bebbb5b1147514c36d08507608f19cc2028fff80aed3137906d092a75a946c1fe1dbee00427716de395369f5360604aebcc0be92e2867937d41b31befe093700f17882a9469df1e5ca8b16403c37b2c3c04818f75aca47e81d83fdb92436c584de2f797225d15410bc9f94998f949215438a94ac3a6ff60509e48abe4c3f79d916b1a8121a9b4876fd6c25fc1f39c4ff0e15b710760c5604dcb1fb2c4611d758c784509d3294b8bf6a39964730741fec02817890e799962bbd72251b75055bb264f96c3e8f4f5e4e0b4745585bcc9f8408979e1f1d33bdf640f4448953a5efbf908fc11acfc617d590cc35ae56c44f41b085f0620a21a2ad202e2bb506976e229ac8edc4612ee1ea2385548a2409ed7024d366a2957edf14c3edc87f846180414bd7214860e9be23debac7b072cc46b130a0fbe40f0ac920ae9427270a791ee72e47b1eb01976fc7ef9256e632421e0dc26106cfc6571697264aeffdf8827a0e37ec5a74bac5b80691f48d5ef96cd1abbce49314ee827e09942d62acdcede59d2480201cb42f3d2c3427fbc00ec03751544e5ee2ec53f7ae34e6943e358bdcd728ac05c0a438d261d3f42d04c5839333f585cfcecc459bb357c7c3772af05', '600400f1aab9e7dbc00126d2', '[{"rol": "paciente", "wrappedKey": "09888a7cfe5b1f43c4f3fae83991c0c7c83afe282af166938bf0bc1313176f2803a5c70d55bd73b7", "ephemeral_pub_hex": "045d2a5f4d6b537b7e9e6b70268a00db12645adf70396baa13b30092b7f7658286aaf320a7e9565182223a559ef73c48145a587b85a1dc4a6d3adbf83c9f0db089"}, {"rol": "farmaceutico", "wrappedKey": "4b5148f99765097c782d1ff8117828c0ef18de14d6d435b23ec068801b6eefe4cfcc6b9991e95bb9", "ephemeral_pub_hex": "044e6c8b56b083732b2059fcd921bf7cdfad5ebab07792a9fef3b1eba9b39aae9e2ee3ba0e8d8e0b48f917ea5876afca50ab1b289a614325dc6cde4e44c0f55e5d"}, {"rol": "doctor", "wrappedKey": "3e78aec105ff99b85cf372ea3457eed6b03c5b5b7b07d37a9fd6afc17ae545e8b58f7a5e13c1d4b0", "ephemeral_pub_hex": "043958bd9f91cb477badcfd76c2503146786916364c49bfff6fac2dd6d470f71548df1ab216e7b589ca8cdd217f2b227b5e6f226b26a78b7e9920134f345425f61"}]', 'activa', '2026-05-20 00:00:00', '2026-06-19 23:59:18.968');


--
-- Name: administradores_id_admin_seq; Type: SEQUENCE SET; Schema: public; Owner: admin
--

SELECT pg_catalog.setval('public.administradores_id_admin_seq', 1, true);


--
-- Name: clinicas_id_clinica_seq; Type: SEQUENCE SET; Schema: public; Owner: admin
--

SELECT pg_catalog.setval('public.clinicas_id_clinica_seq', 2, true);


--
-- Name: llaves_id_llave_seq; Type: SEQUENCE SET; Schema: public; Owner: admin
--

SELECT pg_catalog.setval('public.llaves_id_llave_seq', 36, true);


--
-- Name: recetas_id_receta_seq; Type: SEQUENCE SET; Schema: public; Owner: admin
--

SELECT pg_catalog.setval('public.recetas_id_receta_seq', 3, true);


--
-- Name: roles_id_rol_seq; Type: SEQUENCE SET; Schema: public; Owner: admin
--

SELECT pg_catalog.setval('public.roles_id_rol_seq', 3, true);


--
-- Name: usuarios_id_usuario_seq; Type: SEQUENCE SET; Schema: public; Owner: admin
--

SELECT pg_catalog.setval('public.usuarios_id_usuario_seq', 22, true);


--
-- PostgreSQL database dump complete
--

\unrestrict meoPeqKrWuMoBitEakmqQvYv9KYdF5lFIdbGOcpWlMDggmFEnYNlTw1D19TrSCY

