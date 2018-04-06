##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hummingbird_deployment_activex_cntl_mul_vuln_900161.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Hummingbird Deployment Wizard ActiveX Control Multiple Security Vulnerabilities
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

tag_impact = "Successful exploitation allows execution of arbitrary code.
  Impact Level : Application";

tag_solution = "Set the kill-bit for the affected ActiveX control.
  No patch is available as on 21th October, 2008.";


tag_summary = "This host is installed with Deployment Wizard ActiveX Control and
  is prone to multiple security vulnerabilities. 

  The multiple flaws are due to error in 'SetRegistryValueAsString()',
  'Run()' and 'PerformUpdateAsync()' methods in DeployRun.DeploymentSetup.1
  (DeployRun.dll) ActiveX control.";

tag_affected = "Hummingbird Deployment Wizard version 10.0.0.44 and prior on Windows (all)";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900161");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-10-23 14:16:10 +0200 (Thu, 23 Oct 2008)");
  script_cve_id("CVE-2008-4728");
 script_bugtraq_id(31799);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Denial of Service");
  script_name("Hummingbird Deployment Wizard ActiveX Control Multiple Security Vulnerabilities");

  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "impact" , value : tag_impact);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32337");
  script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/2857");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

wizPath = registry_get_sz(key:"SOFTWARE\Hummingbird\Deployment Wizard",
                          item:"HomeDir");
if(!wizPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$",string:wizPath);
file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1",string:wizPath + 
                    "DeployPkgShell.exe");

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
if(!r){
  close(soc);
  exit(0);
}

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

wizVer = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, offset:1735500);
close(soc);

if(wizVer)
{
  # Grep for version < 10.0.0.44
  if(ereg(pattern:"^[0-9](\..*)|10(\.0(\.0(\.[0-3]?[0-9]|\.4[0-4])?)?)($|[^.0-9])",
          string:wizVer)){
    security_message(0);
  }
}
