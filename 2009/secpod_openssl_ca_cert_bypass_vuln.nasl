###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openssl_ca_cert_bypass_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# OpenSSL CA Certificate Security Bypass Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will let the attacker spoof the SSL cerficate and
  gain sensitive information of the remote user through inserting a malicious
  URL in the contenxt of the openssl certificate.";
tag_affected = "OpenSSL version 0.9.6 or prior.";
tag_insight = "OpenSSL fails to verify the Basic Constraints for an intermediate CA-signed
  certificate.";
tag_solution = "Upgrade to OpenSSL version 1.0.0 or later,
  For further updates refer, http://www.openssl.org/news";
tag_summary = "This host is running OpenSSL and is prone to Security Bypass
  Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900464");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-02 16:07:07 +0100 (Mon, 02 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0653");
  script_name("OpenSSL CA Certificate Security Bypass Vulnerability");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_openssl_detect_lin.nasl");
  script_require_keys("OpenSSL/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include ("version_func.inc");

opensslVer = get_kb_item("OpenSSL/Linux/Ver");
if(opensslVer != NULL)
{
  # Grep for OpenSSL version 0.9.6 or prior.
  if(version_is_less_equal(version:opensslVer, test_version:"0.9.6")){
    security_message(0);
  }
}
