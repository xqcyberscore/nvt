###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_dos_vuln_lin_jun09.nasl 4869 2016-12-29 11:01:45Z teissa $
#
# Denial Of Service Vulnerability in OpenSSL June-09 (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_solution = "Upgrade to OpenSSL version 0.9.8i or later
  http://www.openssl.org/source

  *****
  Note: Vulnerability is related to CVE-2009-1386
  *****

  *****
  This might be a False Positive
  Only version check is being done depending on the publicly available OpenSSL packages. 
  Each vendor might have backported versions of the packages.
  *****";

tag_impact = "Successful exploitation will allow attacker to cause DTLS server crash.
  Impact Level: Application
  Impact Level: Application";
tag_affected = "OpenSSL version prior to 0.9.8i on Linux.";
tag_insight = "A NULL pointer dereference error in ssl/s3_pkt.c file which does not properly
  check the input packets value via a DTLS ChangeCipherSpec packet that occurs
  before ClientHello.";
tag_summary = "This host has OpenSSL installed and is prone to Denial of Service
  vulnerability.";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800809");
  script_version("$Revision: 4869 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-29 12:01:45 +0100 (Thu, 29 Dec 2016) $");
  script_tag(name:"creation_date", value:"2009-06-12 17:18:17 +0200 (Fri, 12 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1386");
 script_bugtraq_id(35174);
  script_name("Denial Of Service Vulnerability in OpenSSL June-09 (Linux)");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name: "solution_type", value: "VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_detect_lin.nasl");
  script_require_keys("OpenSSL/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  
  script_xref(name : "URL" , value : "http://cvs.openssl.org/chngview?cn=17369");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/06/02/1");
  script_xref(name : "URL" , value : "http://rt.openssl.org/Ticket/Display.html?id=1679&user=guest&pass=guest");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

ver = get_app_version(cpe:"cpe:/a:openssl:openssl");
sslVer = ereg_replace(pattern:"-", replace:".", string:ver);
if (sslVer != NULL) {
   # Grep for OpenSSL version < 0.9.8i
   if (version_is_less(version:sslVer, test_version:"0.9.8i")) {
     security_message(0);
     exit(0);
   }
 
   # Grep for OpenSSL version between 0.9.8i and 1.0.0-beta2
   if (version_in_range(version:sslVer, test_version:"0.9.8i",
                        test_version2:"1.0.0.beta1")){
     security_message(0);
   }
}
