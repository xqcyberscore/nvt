###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opensc_insecure_key_generation_vuln.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# OpenSC Incorrect RSA Keys Generation Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900639");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-05-20 10:26:22 +0200 (Wed, 20 May 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-1603");
  script_bugtraq_id(34884);
  script_name("OpenSC Incorrect RSA Keys Generation Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35035");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1295");
  script_xref(name:"URL", value:"http://www.opensc-project.org/pipermail/opensc-announce/2009-May/000025.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPOd");
  script_family("Privilege escalation");
  script_dependencies("gb_opensc_detect.nasl");
  script_mandatory_keys("OpenSC/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain the sensitive
  information or gain unauthorized access to the smartcard.");
  script_tag(name:"affected", value:"OpenSC version prior to 0.11.8 on Linux.");
  script_tag(name:"insight", value:"Security issues are due to,

  - a tool that starts a key generation with public exponent set to 1, an
    invalid value that causes an insecure RSA key.

  - a PKCS#11 module that accepts that this public exponent and forwards it
    to the card.

  - a card that accepts the public exponent and generates the rsa key.");
  script_tag(name:"solution", value:"Upgrade to OpenSC version 0.11.8
  http://www.opensc-project.org/files/opensc");
  script_tag(name:"summary", value:"This host is installed with OpenSC and is prone to Insecure Key
  Generation vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

openscVer = get_kb_item("OpenSC/Ver");
if(openscVer != NULL)
{
  if(version_is_less(version:openscVer, test_version:"0.11.8")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
