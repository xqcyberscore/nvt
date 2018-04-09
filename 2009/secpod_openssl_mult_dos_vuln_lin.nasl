###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openssl_mult_dos_vuln_lin.nasl 9369 2018-04-06 08:36:49Z cfischer $
#
# OpenSSL DTLS Packets Multiple Denial of Service Vulnerabilities (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated by:  Antu Sanadi<santu@secpod.com> on 2010-11-08
# Updated the description part
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

tag_impact = "Successful exploitation will allow attacker to cause denial-of-service
  conditions,crash the client,and exhaust all memory.

  Impact Level: System/Application";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900653");
  script_version("$Revision: 9369 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:36:49 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-05-28 07:14:08 +0200 (Thu, 28 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1377", "CVE-2009-1378", "CVE-2009-1379");
  script_bugtraq_id(35001);
  script_name("OpenSSL DTLS Packets Multiple Denial of Service Vulnerabilities (Linux)");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name: "solution_type", value: "VendorFix");
  script_tag(name:"summary", value:"OpenSSL is prone to multiple Denial of Service Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_detect_lin.nasl");
  script_require_keys("OpenSSL/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);

  exit(0);
}


include ("version_func.inc");
include("host_details.inc");

opensslVer = get_app_version(cpe:"cpe:/a:openssl:openssl");
if(opensslVer == NULL){
  exit(0);
}

opensslVer = ereg_replace(pattern:"-", string:opensslVer, replace: ".");
report =  string("\n Overview: This host is running OpenSSL and is prone to" +
                 "\n Multiple Denial of Service Vulnerabilities (Linux) \n" +
                 "\n Vulnerability Insight:");

vuln_in1 = string("\n  Multiple flaws are due to," +
                  "\n  - The library does not limit the number of buffered DTLS records with a" +
                  "\n    future epoch." +
                  "\n  - An error when processing DTLS messages can be exploited to exhaust all" +
                  "\n    available memory by sending a large number of out of sequence handshake" +
                  "\n    messages.\n");

aff_os1 = string("\n Affected Software/OS: \n" +
                 "OpenSSL version 0.9.8 to version 0.9.8k on Linux.\n");

fix1 = string("\n Fix: Apply patches or upgrade to the latest version." +
              "\n For updates refer tohttp://www.openssl.org/source/ ");

ref1 = string("\n References:" +
              "\n http://secunia.com/advisories/35128" +
              "\n http://cvs.openssl.org/chngview?cn=18188" +
              "\n http://www.openwall.com/lists/oss-security/2009/05/18/1 \n");

vuln_in2 = string("\n Flaws is due to," +
                  "\n - A use-after-free error in the 'dtls1_retrieve_buffered_fragment()' function " +
                  "\n   can be exploited to cause a crash in a client context.\n");

aff_os1 = string("\n  Affected Software/OS:" +
                 "\n  OpenSSL version 1.0.0 Beta2 and prior on Linux.\n");

fix2 = string("\n  Fix: Apply patches or upgrade to the latest version." +
              "\n  http://rt.openssl.org/Ticket/Display.html?id=1923&user=guest&pass=guest \n");

ref2 =string("\n  References:" +
             "\n  https://launchpad.net/bugs/cve/2009-1379" +
             "\n  http://www.openwall.com/lists/oss-security/2009/05/18/4 \n");

if(version_in_range(version:opensslVer, test_version:"0.9.8", test_version2:"0.9.8k"))
{
   security_message(data:string(report, vuln_in1, "\n", aff_os1, fix1,  ref1));
   exit(0);
 }

if(version_is_less_equal(version:opensslVer, test_version:"1.0.0.beta2")){
   security_message(data:string(report, vuln_in2, "\n", aff_os1, fix2, ref2));
}
