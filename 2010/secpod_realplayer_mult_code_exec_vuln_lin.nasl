###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_realplayer_mult_code_exec_vuln_lin.nasl 8258 2017-12-29 07:28:57Z teissa $
#
# RealNetworks RealPlayer Multiple Code Execution Vulnerabilities (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will let the attacker execute arbitrary
  codes within the context of the application and can cause heap overflow
  or allow remote code execution.";
tag_affected = "RealPlayer versions 10.x and prior Linux platforms.";
tag_insight = "Buffer overflow errors exists, when processing a malformed 'ASM Rulebook',
  'GIF file', 'media file', 'IVR file', 'SIPR Codec', 'SMIL file','Skin',
  and 'set_parameter' method.";
tag_solution = "Upgrade to RealPlayer version 11.0.5 or later.
  For updates refer to http://www.real.com/player";
tag_summary = "This host is installed with RealPlayer which is prone to multiple code
  execution vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902108");
  script_version("$Revision: 8258 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-29 08:28:57 +0100 (Fri, 29 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0375", "CVE-2009-0376", "CVE-2009-4241", "CVE-2009-4242",
                "CVE-2009-4243", "CVE-2009-4244", "CVE-2009-4245", "CVE-2009-4246",
                "CVE-2009-4247", "CVE-2009-4248", "CVE-2009-4257");
  script_bugtraq_id(33652, 37880);
  script_name("RealNetworks RealPlayer Multiple Code Execution Vulnerabilities (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38218");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/55794");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0178");
  script_xref(name : "URL" , value : "http://service.real.com/realplayer/security/01192010_player/en/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_realplayer_detect_lin.nasl");
  script_require_keys("RealPlayer/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

rpVer = get_kb_item("RealPlayer/Linux/Ver");
if(isnull(rpVer)){
  exit(0);
}

if(rpVer =~ "^10\.*"){
 security_message(0);
}
