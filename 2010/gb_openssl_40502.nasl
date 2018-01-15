###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_40502.nasl 8374 2018-01-11 10:55:51Z cfischer $
#
# OpenSSL Cryptographic Message Syntax Memory Corruption Vulnerability
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

CPE = "cpe:/a:openssl:openssl";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100668");
 script_version("$Revision: 8374 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-11 11:55:51 +0100 (Thu, 11 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-06-04 13:05:19 +0200 (Fri, 04 Jun 2010)");
 script_bugtraq_id(40502);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-0742");

 script_name("OpenSSL Cryptographic Message Syntax Memory Corruption Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/40502");
 script_xref(name : "URL" , value : "http://www.openssl.org");
 script_xref(name : "URL" , value : "http://www.openssl.org/news/secadv_20100601.txt");

 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_openssl_detect.nasl");
 script_mandatory_keys("OpenSSL/installed");

 script_tag(name : "solution" , value : "Updates are available. Please see the references for more information.");
 script_tag(name : "summary" , value : "OpenSSL is prone to a remote memory-corruption vulnerability.");
 script_tag(name : "vuldetect" , value : "According to its banner, OpenVAS has discovered that the remote
 Webserver is using a version prior to OpenSSL 0.9.8o/1.0.0a which is vulnerable.");
 script_tag(name : "insight" , value : "An attacker can exploit this issue by supplying specially crafted
 structures to a vulnerable application that uses the affected library.");
 script_tag(name : "impact" , value : "Successfully exploiting this issue can allow the attacker to execute
 arbitrary code. Failed exploit attempts will result in a denial-of-service condition.");
 script_tag(name : "affected" , value : "Versions of OpenSSL 0.9.h through 0.9.8n and OpenSSL 1.0.x prior to
 1.0.0a are affected. Note that Cryptographic Message Syntax (CMS)
 functionality is only enabled by default in OpenSSL versions 1.0.x.");

 script_tag(name:"solution_type", value:"VendorFix");

 script_tag(name:"qod_type", value:"remote_banner_unreliable");

 exit(0);
}

include("host_details.inc");

if( ! vers = get_app_version( cpe:CPE ) ) exit(0);

if (vers =~ "^0\.9\.([0-7]([^0-9]|$)|8([^a-z0-9]|[a-n]|$))" ||
    vers =~ "^1\.0\.0(-beta|$)") {

      security_message(port:0);
      exit(0);
    }

exit(99);
