# OpenVAS
# $Id: gb_snmp_authorization.nasl 5505 2017-03-07 10:00:18Z teissa $
# Description: Set information for SNMP authorization in KB.
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105076");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5505 $");
 script_tag(name:"last_modification", value:"$Date: 2017-03-07 11:00:18 +0100 (Tue, 07 Mar 2017) $");
 script_tag(name:"creation_date", value:"2014-09-02 10:42:27 +0200 (Tue, 02 Sep 2014)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("SNMP Authorization");

script_tag(name:"summary", value:"This script allows users to enter the information
required to authorize and login via SNMP.

These data are used by tests that require authentication.");

 script_category(ACT_SETTINGS);
  script_tag(name:"qod_type", value:"remote_banner");
 script_copyright("Copyright 2014 Greenbone Networks GmbH");
 script_family("Credentials");

 script_add_preference(name:"SNMP Community:", type:"password", value:"");

 if (defined_func("snmpv3_get"))
 {
   script_add_preference(name: "SNMPv3 Username:", type: "entry", value:"");
   script_add_preference(name: "SNMPv3 Password:", type: "password", value:"");
   script_add_preference(name: "SNMPv3 Authentication Algorithm:", type: "radio", value: "md5;sha1");
   script_add_preference(name: "SNMPv3 Privacy Password:", type: "password", value: "");
   script_add_preference(name: "SNMPv3 Privacy Algorithm:", type: "radio", value: "aes;des");
 }

 exit(0);
}

snmp_community = script_get_preference( "SNMP Community:" );
if (snmp_community && snmp_community != "(null)") {
  set_kb_item(name: "SNMP/V2/community", value: snmp_community);
  set_kb_item(name: "SNMP/community", value: snmp_community);
}

if (defined_func("snmpv3_get")) {
  snmpv3_username = script_get_preference("SNMPv3 Username:");
  if (snmpv3_username && snmpv3_username != "(null)")
    set_kb_item( name:"SNMP/V3/username", value:snmpv3_username );

  snmpv3_password = script_get_preference("SNMPv3 Password:");
  if (snmpv3_password && snmpv3_password != "(null)")
    set_kb_item( name:"SNMP/V3/password", value:snmpv3_password );

  snmpv3_auth_algo = script_get_preference("SNMPv3 Authentication Algorithm:");
  if (snmpv3_auth_algo && snmpv3_auth_algo != "(null)")
    set_kb_item( name:"SNMP/V3/auth_algorithm", value:snmpv3_auth_algo );

  snmpv3_priv_password = script_get_preference("SNMPv3 Privacy Password:");
  if (snmpv3_priv_password && snmpv3_priv_password != "(null)")
    set_kb_item( name:"SNMP/V3/privacy_password", value:snmpv3_priv_password );

  snmpv3_priv_algo = script_get_preference("SNMPv3 Privacy Algorithm:");
  if (snmpv3_priv_algo && snmpv3_priv_algo != "(null)")
    set_kb_item( name:"SNMP/V3/privacy_algorithm", value:snmpv3_priv_algo );
}

exit( 0 );

