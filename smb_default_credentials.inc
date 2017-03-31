###############################################################################
# OpenVAS Include File
# $Id: smb_default_credentials.inc 5555 2017-03-13 08:59:20Z cfi $
#
# Default Credentials
#
# Authors:
# Ant Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
# $Revision: 5555 $
#
###############################################################################

# user;pass;vendor(multiple vendors separated by ",")

credentials = make_list(
"admin;admin;microsoft",
"admin;1;microsoft",
"admin;12;microsoft",
"admin;123;microsoft",
"admin;1234;microsoft",
"admin;12345;microsoft",
"admin;123456;microsoft",
"admin;1234567;microsoft",
"admin;1234567;microsoft",
"admin;12345678;microsoft",
"admin;123456789;microsoft",
"admin;1234567890;microsoft",
"admin;654321;microsoft",
"admin;54321;microsoft",
"admin;pass;microsoft",
"admin;passwd;microsoft",
"admin;password;microsoft",
"admin;passwort;microsoft",
"admin;qwertz;microsoft",
"admin;qwerty;microsoft",
"administrator;1234567890;microsoft",
"administrator;passwort;microsoft",
"administrator;qwertz;microsoft",
"administrator;qwerty;microsoft",
# The following are from https://www.cert.org/historical/advisories/CA-2003-08.cfm
"administrator;none;microsoft",
"administrator;0;microsoft",
"administrator;000000;microsoft",
"administrator;00000000;microsoft",
"administrator;007;microsoft",
"administrator;1;microsoft",
"administrator;110;microsoft",
"administrator;111;microsoft",
"administrator;111111;microsoft",
"administrator;11111111;microsoft",
"administrator;12;microsoft",
"administrator;121212;microsoft",
"administrator;123;microsoft",
"administrator;123123;microsoft",
"administrator;1234;microsoft",
"administrator;12345;microsoft",
"administrator;123456;microsoft",
"administrator;1234567;microsoft",
"administrator;12345678;microsoft",
"administrator;123456789;microsoft",
"administrator;1234qwer;microsoft",
"administrator;123abc;microsoft",
"administrator;123asd;microsoft",
"administrator;123qwe;microsoft",
"administrator;2002;microsoft",
"administrator;2003;microsoft",
"administrator;2600;microsoft",
"administrator;54321;microsoft",
"administrator;654321;microsoft",
"administrator;88888888;microsoft",
"administrator;Admin;microsoft",
"administrator;Internet;microsoft",
"administrator;Login;microsoft",
"administrator;Password;microsoft",
"administrator;a;microsoft",
"administrator;aaa;microsoft",
"administrator;abc;microsoft",
"administrator;abc123;microsoft",
"administrator;abcd;microsoft",
"administrator;admin;microsoft",
"administrator;admin123;microsoft",
"administrator;administrator;microsoft",
"administrator;alpha;microsoft",
"administrator;asdf;microsoft",
"administrator;computer;microsoft",
"administrator;database;microsoft",
"administrator;enable;microsoft",
"administrator;foobar;microsoft",
"administrator;god;microsoft",
"administrator;godblessyou;microsoft",
"administrator;home;microsoft",
"administrator;ihavenopass;microsoft",
"administrator;login;microsoft",
"administrator;love;microsoft",
"administrator;mypass;microsoft",
"administrator;mypass123;microsoft",
"administrator;mypc;microsoft",
"administrator;mypc123;microsoft",
"administrator;oracle;microsoft",
"administrator;owner;microsoft",
"administrator;pass;microsoft",
"administrator;passwd;microsoft",
"administrator;password;microsoft",
"administrator;pat;microsoft",
"administrator;patrick;microsoft",
"administrator;pc;microsoft",
"administrator;pw;microsoft",
"administrator;pw123;microsoft",
"administrator;pwd;microsoft",
"administrator;qwer;microsoft",
"administrator;root;microsoft",
"administrator;secret;microsoft",
"administrator;server;microsoft",
"administrator;sex;microsoft",
"administrator;super;microsoft",
"administrator;sybase;microsoft",
"administrator;temp;microsoft",
"administrator;temp123;microsoft",
"administrator;test;microsoft",
"administrator;test123;microsoft",
"administrator;win;microsoft",
"administrator;xp;microsoft",
"administrator;xxx;microsoft",
"administrator;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;microsoft",
"administrator;yxcv;microsoft",
"administrator;zxcv;microsoft"
);

uploaded_credentials = get_kb_list( "default_credentials/credentials" );
if( uploaded_credentials ) {

  uploaded_credentials_only = get_kb_item( "default_credentials/uploaded_credentials_only" );

  if( uploaded_credentials_only == "yes" ) {
    credentials = uploaded_credentials;
  } else {
    credentials = make_list( uploaded_credentials, credentials );
  }
}

function try( vendor ) {

  local_var vendor, clist, credential;

  if( ! vendor || isnull( vendor ) || vendor == "" ) return credentials;

  foreach credential( credentials ) {

    if( vendor >!< credential ) continue;

    if( typeof( clist ) == "undef" ) {
       clist = make_list( credential );
    } else {
       clist = make_list( clist, credential );
    }
  }
  return clist;
}
