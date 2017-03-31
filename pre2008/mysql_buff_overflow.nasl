# OpenVAS Vulnerability Test
# $Id: mysql_buff_overflow.nasl 3302 2016-05-12 13:08:27Z benallard $
# Description: MySQL buffer overflow
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Netwok Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "You are running a version of MySQL which is older than 4.0.21.

MySQL is a database which runs on both Linux/BSD and Windows platform.
This version is vulnerable to a length overflow within it's 
mysql_real_connect() function.  The overflow is due to an error in the
processing of a return Domain (DNS) record.  An attacker, exploiting
this flaw, would need to control a DNS server which would be queried
by the MySQL server.  A successful attack would give the attacker
the ability to execute arbitrary code on the remote machine.";

tag_solution = "Upgrade to the latest version of MySQL 4.0.21 or newer";

#  Ref: Lukasz Wojtow

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.14319";
CPE = "cpe:/a:mysql:mysql";

if(description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 3302 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-12 15:08:27 +0200 (Thu, 12 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-0836");
 script_bugtraq_id(10981);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 
 name = "MySQL buffer overflow";
 script_name(name);
 

	


 summary = "Checks for the remote MySQL version";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Gain a shell remotely";
 script_family(family);
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_dependencies("find_service.nasl", "mysql_version.nasl");
 script_require_ports("Services/mysql", 3306);
 script_require_keys("MySQL/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(ereg(pattern:"([0-3]\.[0-9]\.[0-9]|4\.0\.([0-9]|1[0-9]|20)[^0-9])",
  	  string:r))security_message(port);	  

