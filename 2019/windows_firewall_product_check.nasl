###############################################################################
# OpenVAS Vulnerability Test
# $Id: windows_firewall_product_check.nasl 1.0 2018-10-25 12:06:44Z $
#
# Windows WMI Firewall Detection
#
# Authors:
# Stephen Penn <stephen.penn@xqcyber.com>
#
# Copyright:
# Copyright (c) 2017 XQ Digital Resilience Limited
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
    script_oid("1.3.6.1.4.1.25623.1.1.300037");
    script_version("$Revision: 1.0 $");
    script_name("Windows WMI Firewall Detection");
    script_tag(name:"summary", value:"Queries through WMI to get the SecurityCenter2 status of the windows firewall product.");

    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (C) 2017 XQ Digital Resilience Limited.");
    script_family("Product detection");
    script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi", "WMI/access_successful");
    script_dependencies("toolcheck.nasl", "smb_login.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

    exit(0);
}

include("smb_nt.inc");

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
if (domain){
    usrname = domain + '\\' + usrname;
}
passwd = kb_smb_password();


OSVER = get_kb_item("WMI/WMI_OSVER");
OSSP = get_kb_item("WMI/WMI_OSSP");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
OSNAME = get_kb_item("WMI/WMI_OSNAME");


if(!OSVER || OSVER >< "none"){
    log_message(data:"No access to SMB host or firewall is activated or this is not a Windows system.");
    exit(1);
}

if((OSVER == '5.2' || OSVER == '6.0' || OSVER == '6.1' || OSVER == '6.2') && OSTYPE > 1){ #Windows Server 2000, 2003, 2008, 2008 R2 and Server 2012
	log_message(data:"Host appears to be a Windows server.");
	exit(1);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);

if(!handle){
    set_kb_item(name:"WMI/Antivir", value:"error");
    set_kb_item(name:"WMI/Antivir/log", value:"wmi_connect: WMI Connect failed.");
    wmi_close(wmi_handle:handle);
    exit(1);
}

# Query AntivirusProduct
ns = 'root\\SecurityCenter2';
query = 'select displayName, productState from FirewallProduct';
handle = wmi_connect(host:host, username:usrname, password:passwd, ns:ns);
if(!handle){
    log_message(port:0, data:"wmi_connect: WMI Connect failed to query security center.");
    set_kb_item(name:"WMI/Antivir", value:"error");
    exit(1);
}
AntiVirus = wmi_query(wmi_handle:handle, query:query);
wmi_close(wmi_handle:handle);

# If the returned data is null, report the error
if(AntiVirus == ""){
    log_message(data:"WMI Connect returned an empty string.");
    exit(1);
}

log_message(data:AntiVirus);
exit(0);
