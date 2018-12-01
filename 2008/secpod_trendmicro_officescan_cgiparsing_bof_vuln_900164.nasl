##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_trendmicro_officescan_cgiparsing_bof_vuln_900164.nasl 12602 2018-11-30 14:36:58Z cfischer $
# Description: Trend Micro OfficeScan CGI Parsing Buffer Overflow Vulnerability
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900164");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-10-29 14:53:11 +0100 (Wed, 29 Oct 2008)");
  script_bugtraq_id(31859);
  script_cve_id("CVE-2008-3862");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Buffer overflow");
  script_name("Trend Micro OfficeScan CGI Parsing Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32005/");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2008/Oct/0169.html");
  script_xref(name:"URL", value:"http://www.trendmicro.com/ftp/documentation/readme/OSCE_7.3_CriticalPatch_B1374_readme.txt");
  script_xref(name:"URL", value:"http://www.trendmicro.com/ftp/documentation/readme/OSCE_8.0_sp1p1_CriticalPatch_B3110_readme.txt");
  script_xref(name:"URL", value:"http://www.trendmicro.com/ftp/products/patches/OSCE_8.0_SP1_Patch1_Win_EN_CriticalPatch_B3110.exe");
  script_xref(name:"URL", value:"http://www.trendmicro.com/ftp/products/patches/OSCE_7.3_Win_EN_CriticalPatch_B1374.exe");

  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Allows an attacker to execute arbitrary code, which may facilitate a complete
  compromise of vulnerable system.");

  script_tag(name:"affected", value:"TrendMicro OfficeScan Corporate Edition 7.3 Build prior to 1374.

  TrendMicro OfficeScan Corporate Edition 8.0 Build prior to 3110.");

  script_tag(name:"solution", value:"Apply the referenced updates.");

  script_tag(name:"summary", value:"This host is installed with Trend Micro OfficeScan and is prone to
  stack based buffer overflow vulnerability.

  The vulnerability is due to boundary error in the CGI modules when
  processing specially crafted HTTP request.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\TrendMicro\NSC\PFW";
scanPath = registry_get_sz(key:key, item:"InstallPath");

if(!scanPath){
  exit(0);
}

scanPath += "PccNTMon.exe";

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:scanPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:scanPath);

name   =  kb_smb_name();
login  =  kb_smb_login();
pass   =  kb_smb_password();
domain =  kb_smb_domain();
port   =  kb_smb_transport();

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

r = smb_session_request(soc:soc, remote:name);
if(!r){
  close(soc);
  exit(0);
}

prot = smb_neg_prot(soc:soc);
if(!prot){
  close(soc);
  exit(0);
}

r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain,
                      prot:prot);
if(!r){
  close(soc);
  exit(0);
}

uid = session_extract_uid(reply:r);
if(!uid){
  close(soc);
  exit(0);
}

r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
tid = tconx_extract_tid(reply:r);
if(!tid){
  close(soc);
  exit(0);
}

fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
if(!fid){
  close(soc);
  exit(0);
}

fileVer = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid);

if(egrep(pattern:"^(8\.0(\.0(\.[0-2]?[0-9]?[0-9]?[0-9]|\.30[0-9][0-9]|\.310" +
                 "[0-9])?)?)$", string:fileVer)){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
