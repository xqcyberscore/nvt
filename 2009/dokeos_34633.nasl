###############################################################################
# OpenVAS Vulnerability Test
# $Id: dokeos_34633.nasl 9583 2018-04-24 09:48:35Z ckuersteiner $
#
# Dokeos 'whoisonline.php' Remote Code Execution Vulnerability
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = 'cpe:/a:dokeos:dokeos';

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100159");
 script_version("$Revision: 9583 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-24 11:48:35 +0200 (Tue, 24 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-04-24 20:04:08 +0200 (Fri, 24 Apr 2009)");
 script_bugtraq_id(34633);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_tag(name: "solution_type", value: "VendorFix");

 script_name("Dokeos 'whoisonline.php' Remote Code Execution Vulnerability");

 script_tag(name:"qod_type", value:"remote_banner");

 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("dokeos_detect.nasl");
 script_mandatory_keys("dokeos/installed");

 script_tag(name: "summary", value: "Dokeos is prone to a remote code-execution vulnerability because the software
fails to adequately sanitize user-supplied input.

Exploiting this issue could allow an attacker to execute arbitrary code in the context of the vulnerable
application.

Dokeos prior to version 1.8.5 are vulnerable.");

 script_xref(name: "URL", value: "http://www.securityfocus.com/bid/34633");

 exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.8.5")) {
  security_message(port: port);
  exit(0);
}   

exit(99);
