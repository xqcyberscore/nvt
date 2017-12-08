# OpenVAS Vulnerability Test
# $Id: mysql_hotcopy_tempfile.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: MySQL mysqlhotcopy script insecure temporary file
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

tag_summary = "You are running a version of MySQL which is older than version 4.0.21.

mysqlhotcopy is reported to contain an insecure temporary file creation 
vulnerability. 

The result of this is that temporary files created by the application may 
use predictable filenames. 

A local attacker may also possibly exploit this vulnerability to execute 
symbolic link file overwrite attacks. 

*** Note : this vulnerability is local only";

tag_solution = "Upgrade to the latest version of MySQL 4.0.21 or newer";

#  Ref:  Jeroen van Wolffelaar <jeroen@wolffelaar.nl>

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.14343";
CPE = "cpe:/a:mysql:mysql";

if(description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(10969);
 script_cve_id("CVE-2004-0457");

 script_tag(name:"qod_type", value:"remote_banner_unreliable");

 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

 
 name = "MySQL mysqlhotcopy script insecure temporary file";
 script_name(name);
 

	


 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 script_family("Databases");
 script_dependencies("mysql_version.nasl");
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
if(!r = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(ereg(pattern:"3\.|4\.0\.([0-9]|1[0-9]|20)[^0-9]", string:r))security_message(port);	  

