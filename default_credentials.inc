###############################################################################
# OpenVAS Vulnerability Test
# $Id: default_credentials.inc 7851 2017-11-21 14:36:26Z asteins $
#
# Default Credentials
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software
# Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
# USA.
#
# $Revision: 7851 $
#
###############################################################################

# user;pass;vendor(multiple vendors separated by ",")
credentials = make_list(
"root;pass;axis",
"root;calvin;dell",
"root;password;korenix",
"MGR;REGO;hp",
"MAIL;TELESUP;hp",
"storwatch;specialist;ibm",
"admin;hp.com;hp",
"user;public;compaq",
"MGR;HPP196;hp",
"at4400;at4400;alcatel",
"FIELD;HPWORD PUB;hp",
"root;letacla;alcatel",
"HELLO;MGR.SYS;hp",
"mtch;mtch;alcatel",
"User;none;bay networks,dlink",
"device;device;apc",
"cisco;cisco;cisco",
"Administrator;admin;cisco,conexant,corecess,gvc",
"MANAGER;COGNOS;hp",
"MAIL;HPOFFICE;hp",
"admin;diamond;cisco",
"patrol;patrol;bmc",
"MAIL;MAIL;hp",
"admin;changeme;cisco",
"admin;default;cisco",
"dhs3pms;dhs3pms;alcatel",
"root;Mau'dib;celerity",
"login;password;efficient",
"PFCUser;240653C9467E45;compaq",
"Administrator;letmein;integral",
"davox;davox;davox",
"debug;synnet;3com",
"MANAGER;SECURITY;hp",
"FIELD;SERVICE;hp",
"sa;none;cisco,davox",
"Cisco;Cisco;cisco",
"root;attack;cisco",
"guest;none;cisco,edimax,intel",
"MGR;CONV;hp",
"MANAGER;TELESUP;hp",
"volition;volition;3m",
"administrator;administrator;compaq",
"FIELD;HPP187 SYS;hp",
"public;none;ericsson",
"cmaker;cmaker;cisco",
"OPERATOR;DISC;hp",
"OPERATOR;SUPPORT;hp",
"admin;synnet;3com",
"SYSDBA;masterkey;interbase",
"PBX;PBX;dictaphone",
"apc;apc;apc",
"acc;acc;andover controls",
"root;tslinux;cyclades",
"tech;tech;3com",
"root;ascend;ascend",
"operator;none;3com",
"FIELD;MANAGER;hp",
"MGR;WORD;hp",
"root;root;ambit,avaya",
"OPERATOR;COGNOS;hp",
"super;surt;cyclades",
"netrangr;attack;cisco",
"install;llatsni;alcatel",
"Manager;none;bay networks",
"admin;hello;intel,shiva",
"admin;bintec;bintec",
"craft;none;avaya",
"MGR;TELESUP;hp",
"manager;manager;3com",
"MANAGER;TCH;hp",
"cgadmin;cgadmin;cyberguard",
"adm;none;3com",
"monitor;monitor;3com",
"MGR;VESOFT;hp",
"admin;my_DEMARC;demarc",
"WP;HPOFFICE;hp",
"manager;friend;Allied",
"diag;switch;alcatel",
"Anonymous;none;compaq,hp",
"netman;netman;ericsson",
"root;davox;davox",
"MANAGER;HPOFFICE;hp",
"MGR;HPOFFICE;hp",
"Guest;none;intel",
"admin;radius;funk software",
"security;security;3com,bay networks",
"admin;epicrouter;e-tech",
"supervisor;supervisor;everfocus",
"MGR;RJE;hp",
"MAIL;MPE;hp",
"root;none;3com,allied,buffalo,intel",
"DTA;TJM;aspect",
"admin;cisco;cisco",
"NICONEX;NICONEX;intel",
"MGR;ROBELLE;hp",
"FIELD;SUPPORT;hp",
"FIELD;HPONLY;hp",
"MGR;CNAS;hp",
"RSBCMON;SYS;hp",
"HELLO;OP.OPERATOR;hp",
"NETWORK;NETWORK;dictaphone",
"admin;linga;alteon",
"admin;switch;alcatel",
"hscroot;abc123;ibm",
"admin;none;3com,aceex,alteon,telekom,dlink,enterasys,extreme networks,fortinet,hp,ibm,intel",
"Administrator;the same all over;bmc",
"MGR;XLSERVER;hp",
"HELLO;MANAGER.SYS;hp",
"kermit;kermit;alcatel",
"MGR;CAROLIAN;hp",
"ADVMAIL;HP;hp",
"D-Link;D-Link;dlink",
"MDaemon;MServer;deerfield",
"MGR;ITF3000;hp",
"admin;netadmin;enterasys",
"admin;secure;ADIC",
"admin;system;cisco",
"tech;none;3com",
"customer;none;aspect",
"MGR;SYS;hp",
"MGR;NETBASE;hp",
"root;fivranne;brocade",
"bbsd-client;changeme2;cisco",
"user;user;compaq",
"vt100;public;ibm",
"root;ROOT500;avaya",
"cellit;cellit;cellit",
"anonymous;none;compaq",
"netman;none;cabletron",
"Administrator;none;3com",
"MAIL;REMOTE;hp",
"manager;admin;allied",
"intel;intel;intel",
"MGR;SECURITY;hp",
"MGR;HPP189;hp",
"operator;operator;compaq,everfocus",
"mediator;mediator;celerity",
"MGR;HPDESK;hp",
"adminttd;adminttd;3com",
"sysadm;anicust;accelerated networks",
"setup;setup;intel",
"HELLO;FIELD.SUPPORT;hp",
"mtcl;mtcl;alcatel",
"MGR;CCC;hp",
"bbsd-client;null;cisco",
"root;cms500;avaya",
"admin;comcomcom;3com",
"MANAGER;ITF3000;hp",
"admin;password;3com,adic,brocade,ciphertrust,ibm",
"OPERATOR;SYSTEM;hp",
"IntraStack;Asante;asante",
"MGR;INTX3;hp",
"Root;none;3com,ambit",
"admin;1234;edimax",
"root;tini;dallas semiconductors",
"FIELD;MGR;hp",
"anonymous;any@;datawizard.net",
"Administrator;changeme;cisco",
"FIELD;LOTUS;hp",
"root;permit;alcatel",
"adfexc;adfexc;alcatel",
"root;default;f5",
"halt;tlah;alcatel",
"MGR;HPP187;hp",
"PCUSER;SYS;hp",
"readonly;lucenttech2;ascend",
"SPOOLMAN;HPOFFICE;hp",
"MGR;HPONLY;hp",
"MANAGER;SYS;hp",
"diag;danger;avaya",
"user;none;dlink",
"craft;crftpw;avaya",
"login;admin;efficient",
"admin;admin;huawei,3com,allied,alteon,amitech,billon,checkpoint,cisco,com3,davox,dlink,draytek,dynalink,everfocus,flowpoint,foundry networks,hp",
"client;client;alcatel",
"OPERATOR;SYS;hp",
"MGR;COGNOS;hp",
"manuf;xxyyzz;avaya",
"3comcso;RIP000;3com",
"dhs3mt;dhs3mt;alcatel",
"ADVMAIL;HPOFFICE DATA;hp",
"superadmin;secret;ibm",
"superuser;none;asante",
"recovery;recovery;3com",
"NETOP;none;dictaphone",
"IntraSwitch;Asante;asante",
"cisco;none;cisco",
"rwa;rwa;accelar",
"root;alpine;iOS",
"mobile;dottie;iOS",
"admin;PASS;Lantronix",
"TANDBERG;none;Tandberg",
"skyboxview;skyboxview;SkyBOX",
"pi;raspberry;raspberry",
"root;toor;kali linux,backtrack linux",
"msfadmin;msfadmin;metasploitable",
"root;abcd1234;trango"
);

uploaded_credentials = get_kb_list( "default_credentials/credentials" );

if( uploaded_credentials ) {

  uploaded_credentials_only = get_kb_item( "default_credentials/uploaded_credentials_only" );

  if( uploaded_credentials_only == "yes" ) {

    credentials = uploaded_credentials;

  } else {

    credentials = make_list(uploaded_credentials, credentials);

  }
}

function try( vendor ) {

  local_var vendor, clist, credential;

  if( ! vendor || isnull( vendor ) || vendor == "" ) return credentials;

  foreach credential( credentials ) {

    if( vendor >!< credential ) continue;

    if( typeof( clist ) == "undef") {
       clist = make_list( credential );
    } else {
       clist = make_list( clist, credential );
    }
  }
  return clist;
}
