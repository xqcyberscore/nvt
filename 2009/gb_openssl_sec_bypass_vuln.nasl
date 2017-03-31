###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_sec_bypass_vuln.nasl 4918 2017-01-02 14:56:10Z cfi $
#
# libcrypt-openssl-dsa-perl Security Bypass Vulnerability in OpenSSL
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

tag_impact = "Successful exploitation will let the attacker spoof the user data with
  malicious DSA signature to gain access to user's sensitive information.
  Impact Level: Application";
tag_affected = "OpenSSL version prior to 0.9.8j on Linux.";
tag_insight = "The flaw is due to libcrypt-openssl-dsa-perl which does not properly check
  the return value from the OpenSSL DSA_verify and DSA_do_verify functions.";
tag_solution = "Upgrade to version 0.9.8j
  http://www.openssl.org/source/";
tag_summary = "This host has OpenSSL installed and is prone to security bypass
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800336");
  script_version("$Revision: 4918 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-02 15:56:10 +0100 (Mon, 02 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-01-09 13:48:55 +0100 (Fri, 09 Jan 2009)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2009-0129","CVE-2008-5077");
  script_bugtraq_id(33150);
  script_name("libcrypt-openssl-dsa-perl Security Bypass Vulnerability in OpenSSL");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2009/01/12/4");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=511519");

  script_tag(name:"solution_type", value: "VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_detect_lin.nasl");
  script_mandatory_keys("OpenSSL/Linux/Ver");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);

  exit(0);
}


include("version_func.inc");

sslVer = get_kb_item("OpenSSL/Linux/Ver");
if(!sslVer){
  exit(0);
}

# Check for OpenSSL version prior to 0.9.8j
if(version_is_less(version:sslVer, test_version:"0.9.8j")){
  report = 'Installed version: ' + sslVer + '\n' + 
           'Fixed version:     0.9.8j';
  security_message(0, data:report);
}
