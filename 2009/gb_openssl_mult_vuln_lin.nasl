###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_mult_vuln_lin.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# OpenSSL Multiple Vulnerabilities (Linux)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800259");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0590", "CVE-2009-0591", "CVE-2009-0789");
  script_bugtraq_id(34256);
  script_name("OpenSSL Multiple Vulnerabilities (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34411");
  script_xref(name:"URL", value:"http://www.openssl.org/news/secadv_20090325.txt");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Mar/1021905.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_detect_lin.nasl");
  script_mandatory_keys("OpenSSL/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause memory access violation,
  security bypass or can cause denial of service.");
  script_tag(name:"affected", value:"OpenSSL version prior to 0.9.8k on all running platform.");
  script_tag(name:"insight", value:"- error exists in the 'ASN1_STRING_print_ex()' function when printing
    'BMPString' or 'UniversalString' strings which causes invalid memory
    access violation.

  - 'CMS_verify' function incorrectly handles an error condition when
    processing malformed signed attributes.

  - error when processing malformed 'ASN1' structures which causes invalid
    memory access violation.");
  script_tag(name:"solution", value:"Upgrade to OpenSSL version 0.9.8k
  http://openssl.org");
  script_tag(name:"summary", value:"This host is installed with OpenSSL and is prone to Multiple
  Vulnerabilities.");
  exit(0);
}


include("version_func.inc");

opensslVer = get_kb_item("OpenSSL/Linux/Ver");
if(!opensslVer){
  exit(0);
}

if(version_is_less(version:opensslVer, test_version:"0.9.8k")){
  report = 'Installed version: ' + opensslVer + '\n' +
           'Fixed version:     0.9.8k';
  security_message(0, data:report);
}
