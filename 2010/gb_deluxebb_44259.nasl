###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_deluxebb_44259.nasl 9583 2018-04-24 09:48:35Z ckuersteiner $
#
# DeluxeBB 'xthedateformat' Parameter SQL Injection Vulnerability
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

CPE = 'cpe:/a:deluxebb:deluxebb';

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100862");
 script_version("$Revision: 9583 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-24 11:48:35 +0200 (Tue, 24 Apr 2018) $");
 script_tag(name:"creation_date", value:"2010-10-21 13:52:26 +0200 (Thu, 21 Oct 2010)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-4151");
 script_bugtraq_id(44259);

 script_name("DeluxeBB 'xthedateformat' Parameter SQL Injection Vulnerability");

 script_tag(name: "solution_type", value: "VendorFix");

 script_xref(name: "URL", value: "https://www.securityfocus.com/bid/44259");
 script_xref(name: "URL", value: "http://www.deluxebb.com/");
 script_xref(name: "URL", value: "http://www.securityfocus.com/archive/1/514374");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("deluxeBB_detect.nasl");
 script_mandatory_keys("deluxebb/installed");

 script_tag(name: "summary", value: "DeluxeBB is prone to an SQL-injection vulnerability because it fails to
sufficiently sanitize user-supplied data before using it in an SQL query.

Exploiting this issue could allow an attacker to compromise the application, access or modify data, or exploit
latent vulnerabilities in the underlying database.

DeluxeBB 1.3 and prior are vulnerable.");

 exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.3")) {
  security_message(port:port);
  exit(0);
}

exit(99);
