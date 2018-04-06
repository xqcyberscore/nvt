##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_blue_coat_k9_web_prot_bof_vuln_900103.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Blue Coat K9 Web Protection Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

tag_impact = "Successful exploitation could allow remote attackers to cause
stack based buffer overflow by sending specially crafted malicious
code containing and overly long http version information and
reference header.

Impact Level : System";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_affected = "Blue Coat K9 Web Protection versions 3.2.44 and prior on Windows (All)";

tag_insight = "The flaws exist due to errors in filter services (k9filter.exe) when handling

- http version information in responses from a centralised server
  (sp.cwfservice.net).

- Referer: headers during access to the web-based K9 Web Protection
  Administration interface.";


tag_summary = "This host is installed with Blue Coat K9 Web Protection, which is
prone to stack based buffer overflow vulnerability.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900103");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_bugtraq_id(30464,30463);
 script_cve_id("CVE-2007-2752");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_family("Buffer overflow");
 script_name("Blue Coat K9 Web Protection Multiple Buffer Overflow Vulnerabilities");
 script_dependencies("secpod_reg_enum.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2007-61/advisory/");
 script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2007-64/advisory/");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 script_tag(name:"solution_type", value:"WillNotFix");
 exit(0);
}

include("smb_nt.inc");

if (!get_kb_item("SMB/WindowsVersion")){
       exit(0);
}

blueVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\Uninstall\Blue Coat K9 Web Protection",
                          item:"DisplayVersion");

if(egrep(pattern:"^([0-2]\..*|3\.([01]\..*|2\.([0-3]?[0-9]|4[0-4])))$",
         string:blueVer)) {
       security_message(0);
}
