##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_trendmicro_officescan_auth_bypass_vuln_900205.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Trend Micro Web Management Authentication Bypass Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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

tag_impact = "Remote users can gain administrative access on the target
        application and allow arbitrary code execution.
 Impact Level : Application.";

tag_solution = "Partially Fixed.
 Fix is available for Trend Micro OfficeScan 8.0 and Worry-Free Business Security 5.0.
 http://www.trendmicro.com/ftp/products/patches/OSCE_8.0_SP1_Win_EN_CriticalPatch_B2402.exe
 http://www.trendmicro.com/ftp/products/patches/OSCE_8.0_Win_EN_CriticalPatch_B1351.exe 
 http://www.trendmicro.com/ftp/products/patches/OSCE_8.0_SP1_Patch1_Win_EN_CriticalPatch_B3037.exe
 http://www.trendmicro.com/ftp/products/patches/WFBS_50_WIN_EN_CriticalPatch_B1404.exe

 *****
 NOTE : Ignore this warning if above mentioned patch is applied already.
 *****";


tag_affected = "Trend Micro Client Server Messaging Security (CSM) versions 3.5 and 3.6
        Trend Micro OfficeScan Corporate Edition versions 7.0 and 7.3
        Trend Micro OfficeScan Corporate Edition version 8.0
        Trend Micro Worry-Free Business Security (WFBS) version 5.0";

tag_insight = "The flaw is due to insufficient entropy in a random session
        token used to identify an authenticated manager using the web console.";


tag_summary = "This Remote host is installed with Trend Micro OfficeScan, which
 is prone to Authentication Bypass Vulnerability.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900205");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-27 11:53:45 +0200 (Wed, 27 Aug 2008)");
 script_bugtraq_id(30792);
 script_cve_id("CVE-2008-2433");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_family("Privilege escalation");
 script_name("Trend Micro Web Management Authentication Bypass Vulnerability");

 script_dependencies("secpod_reg_enum.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_xref(name : "URL" , value : "http://secunia.com/advisories/31373/");
 script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Aug/1020732.html");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 exit(0);
}

 include("smb_nt.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 scanVer = registry_get_sz(key:"SOFTWARE\TrendMicro\OfficeScan\service" + 
                               "\Information", item:"Server_Version");
 if(!scanVer){
	exit(0);
 }

 if(egrep(pattern:"^([0-7]\..*|8\.0)$", string:scanVer)){
	security_message(0);
 }
