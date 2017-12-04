# OpenVAS Vulnerability Test
# $Id: toolcheck.nasl 7975 2017-12-04 06:44:10Z cfischer $
# Description: Initializing routine for checking presence of helper tools
#
# Authors:
# Jan-Oliver Wagner <Jan-Oliver.Wagner@greenbone.net>
# Felix Wolfsteller <felix.wolfsteller@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

#
# TODO: Extract a function that performs checks for presence of tools
# (unversioned) and sets the kb entries accordingly, modifies the summary etc.
# e.g. all_tools_available = find_tool ("pnscan", "Description of Effect");
#

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.810000");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 7975 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-04 07:44:10 +0100 (Mon, 04 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-08-17 09:05:44 +0200 (Mon, 17 Aug 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("Availability of scanner helper tools");


 script_category(ACT_INIT);
  script_tag(name:"qod_type", value:"remote_banner");

 script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
 script_family("General");

 script_add_preference(name:"Perform tool check", type:"checkbox", value:"yes");
 script_add_preference(name:"Silent tool check",  type:"checkbox", value:"yes");

 script_tag(name : "summary" , value : "This routine checks for the presence of various tools that
 support the scan engine and also tests the version of the scan
 engine itself. If some tools are not accessible for the
 scan engine, one or more NVTs could not be executed properly.

 The consequence might be that certain vulnerabilities are missed
 because respective tests are not performed.");
 exit(0);
}

# Silent exit if no check to perform
perform_check = script_get_preference("Perform tool check");
if (perform_check == "no")
  exit(0);

include ("version_func.inc");

all_tools_available = TRUE;

summary = "
The following tools are not accessible for the scan server.
Please contact the responsible administrator for the
OpenVAS scan engine to make the missing tool(s) available.
";

#
# Test for presence of Ovaldi
#

sufficient_ovaldi_found = FALSE;

if (find_in_path("ovaldi")){
  ovaldi_out = pread(cmd: "ovaldi", argv: make_list("ovaldi", "-h"));
  foreach line(split(ovaldi_out)){
    v = eregmatch(string: line, pattern: 'Version: ([0-9.]*) Build: ([0-9.]*)');
    if (! isnull(v)){
      found_version = v[1] + '.';
      found_version = found_version + v[2];
      if (version_is_greater_equal (version:found_version,
                                    test_version: "5.5.23")){
        set_kb_item(name: "Tools/Present/ovaldi", value: TRUE);
        set_kb_item(name: "Tools/Missing/ovaldi", value: FALSE);
        sufficient_ovaldi_found = TRUE;
        break;
      }
    }
  }
}


#
# Attention, the order of the next two checks is imporant.
# By setting "Tools/(Missing|Present)/ovaldi", we pretend a missing ovaldi in
# case of an openvas server that does not support oval nicely (enough)!
#
if (!sufficient_ovaldi_found) {
  set_kb_item(name: "Tools/Missing/ovaldi", value: TRUE);
  set_kb_item(name: "Tools/Present/ovaldi", value: FALSE);
  summary = summary + "
Tool:   ovaldi 5.5.23 or newer
Effect: No NVTs of family 'OVAL definitions' will be executed.
        This family is only visible in case your installation
        includes OVAL files.
";
  all_tools_available = FALSE;
}

#
# Check for (built-in) wmi and smb support
#
if (wmi_versioninfo()) {
    # Supported
    set_kb_item(name: "Tools/Present/wmi", value: TRUE);
    set_kb_item(name: "Tools/Missing/wmi", value: FALSE);
}
else {
    summary = summary + "
Tool:   WMI Client (OpenVAS not furnished with WMI client functionality)
Effect: Any NVTs that do rely on the built-in WMI functionality will
        not be executed. If you did not provide WMI credentials
        or do not scan host with Windows operating systems, the absence
        will not reduce the number of executed NVTs.
        Most likely reduced are compliance tests and OVAL NVTs.
";
    # set kb
    set_kb_item(name: "Tools/Present/wmi", value: FALSE);
    set_kb_item(name: "Tools/Missing/wmi", value: TRUE);
    all_tools_available = FALSE;
}


# built-in SMB?
if (smb_versioninfo()){
  set_kb_item(name: "Tools/Present/smb", value: TRUE);
  set_kb_item(name: "Tools/Missing/smb", value: FALSE);
}
else {
    summary = summary + "
Tool:   WMI Client (OpenVAS not furnished with SMB client functionality)
Effect: Any NVTs that do rely on the built-in SMB functionality will
        not be executed. If you did not provide SMB credentials
        or do not scan host with Windows operating systems, the absence
        will not reduce the number of executed NVTs.
        Most likely reduced are compliance tests and OVAL NVTs.
";
  set_kb_item(name: "Tools/Present/smb", value: FALSE);
  set_kb_item(name: "Tools/Missing/smb", value: TRUE);
  all_tools_available = FALSE;
}


#
# NMap 4.0+ check
#
sufficient_nmap_found = FALSE;
if (find_in_path("nmap")){
  nmap_v_out = pread(cmd: "nmap", argv: make_list("nmap", "-V"));
  if (nmap_v_out != NULL)
    {
      ver = ereg_replace(pattern: ".*nmap version ([0-9.]+).*", string: nmap_v_out, replace: "\1", icase: TRUE);
      if (ver == nmap_v_out) ver = NULL;
    }
  if (ver =~ "^[4-9]\.")
    {
      sufficient_nmap_found = TRUE;
    }

  ## Nmap 5.21 check
  if (version_is_equal(version:ver, test_version:"5.21"))
  {
    nmap_check_nse_support = pread(cmd: "nmap", argv: make_list("nmap", "--help"));
    if(nmap_check_nse_support != 0) {
      if("script-updatedb" >!< nmap_check_nse_support) {
	summary = summary + "
Tool:   Nmap 5.21
Effect: Nmap was build without support for NSE scripts. Wrappers for
        Nmap's NSE scripts will not work.
";
      } else {

  	set_kb_item(name: "Tools/Present/nmap5.21", value: TRUE);
      }	  
    }
  }

  ## Nmap 5.51 check
  if (version_is_equal(version:ver, test_version:"5.51"))
  {
    nmap_check_nse_support = pread(cmd: "nmap", argv: make_list("nmap", "--help"));
    if(nmap_check_nse_support != 0) {
      if("script-updatedb" >!< nmap_check_nse_support) {
        summary = summary + "
Tool:   Nmap 5.51
Effect: Nmap was build without support for NSE scripts. Wrappers for
        Nmap's NSE scripts will not work.
";
      } else {
        set_kb_item(name: "Tools/Present/nmap5.51", value: TRUE);
      }
    }
  }

  ## Nmap 6.01 check
  if (version_is_equal(version:ver, test_version:"6.01"))
  {
    nmap_check_nse_support = pread(cmd: "nmap", argv: make_list("nmap", "--help"));
    if(nmap_check_nse_support != 0) {
      if("script-updatedb" >!< nmap_check_nse_support) {
        summary = summary + "
Tool:   Nmap 6.01
Effect: Nmap was build without support for NSE scripts. Wrappers for
        Nmap's NSE scripts will not work.
";
      } else {
        set_kb_item(name: "Tools/Present/nmap6.01", value: TRUE);
      }
    }
  }
}

if (sufficient_nmap_found == TRUE){
  set_kb_item(name: "Tools/Present/nmap", value: TRUE);
  set_kb_item(name: "Tools/Missing/nmap", value: FALSE);
}
else{
    summary = summary + "
Tool:   nmap 4.0 or newer
Effect: Port scanning and service detection based on nmap is not available.
";
  set_kb_item(name: "Tools/Present/nmap", value: FALSE);
  set_kb_item(name: "Tools/Missing/nmap", value: TRUE);
  all_tools_available = FALSE;
}

#
# Test for presence of pd (phrasendrescher)
# TODO: Migh find a  pd executable from "pure data", disambiguate
if ( find_in_path("pd") ){
  set_kb_item(name: "Tools/Present/pd", value: TRUE);
  set_kb_item(name: "Tools/Present/pd_or_ncrack", value: TRUE);
  set_kb_item(name: "Tools/Missing/pd", value: FALSE);
} else {
  set_kb_item(name: "Tools/Missing/pd", value: TRUE);
  set_kb_item(name: "Tools/Present/pd", value: FALSE);
  summary = summary + "
Tool:   pd/phrasendrescher
Effect: The phrasendrescher wrapper will not deliver results.
        This NVT could otherwise attempt to find ssh accounts and passwords
        brute force.
";
  all_tools_available = FALSE;
}

#
# Test for presence of ncrack
#
if ( find_in_path("ncrack") ){
  set_kb_item(name: "Tools/Present/ncrack", value: TRUE);
  set_kb_item(name: "Tools/Present/pd_or_ncrack", value: TRUE);
  set_kb_item(name: "Tools/Missing/ncrack", value: FALSE);
} else {
  set_kb_item(name: "Tools/Missing/ncrack", value: TRUE);
  set_kb_item(name: "Tools/Present/ncrack", value: FALSE);
  summary = summary + "
Tool:   ncrack
Effect: ncrack wrappers will not deliver results.
        The ncrack wrappers could otherwise attempt to find ftp, ssh and
        telnet accounts and passwords brute-force.
";
  all_tools_available = FALSE;
}

#
# Test for presence of portbunny
#
if ( find_in_path("portbunny") ){
  set_kb_item(name: "Tools/Present/portbunny", value: TRUE);
  set_kb_item(name: "Tools/Missing/portbunny", value: FALSE);
} else {
  set_kb_item(name: "Tools/Missing/portbunny", value: TRUE);
  set_kb_item(name: "Tools/Present/portbunny", value: FALSE);
  summary = summary + "
Tool:   portbunny
Effect: Port scanning based on portbunny is not available.
";
  all_tools_available = FALSE;
}

#
# Test for presence of pnscan
#
if ( find_in_path("pnscan") ){
  set_kb_item(name: "Tools/Present/pnscan", value: TRUE);
  set_kb_item(name: "Tools/Missing/pnscan", value: FALSE);
} else {
  set_kb_item(name: "Tools/Missing/pnscan", value: TRUE);
  set_kb_item(name: "Tools/Present/pnscan", value: FALSE);
  summary = summary + "
Tool:   pnscan
Effect: Port scanning based on pnscan is not available.
";
  all_tools_available = FALSE;
}

#
# Test for presence of strobe
#
if ( find_in_path("strobe") ){
  set_kb_item(name: "Tools/Present/strobe", value: TRUE);
  set_kb_item(name: "Tools/Missing/strobe", value: FALSE);
} else {
  set_kb_item(name: "Tools/Missing/strobe", value: TRUE);
  set_kb_item(name: "Tools/Present/strobe", value: FALSE);
  summary = summary + "
Tool:   strobe
Effect: Port scanning based on strobe is not available.
";
  all_tools_available = FALSE;
}

#
# Test for presence of amap
#
if ( find_in_path("amap6") || find_in_path("amap") ){

  set_kb_item(name: "Tools/Present/amap", value: TRUE);
  set_kb_item(name: "Tools/Missing/amap", value: FALSE);

  if ( find_in_path("amap6") ){
    set_kb_item(name: "Tools/Present/amap/bin", value: "amap6");
  } else {
    set_kb_item(name: "Tools/Present/amap/bin", value: "amap");
  }
} else {
  set_kb_item(name: "Tools/Missing/amap", value: TRUE);
  set_kb_item(name: "Tools/Present/amap", value: FALSE);
  summary = summary + "
Tool:   amap
Effect: Port scanning and service detection based on amap is not available.
";
  all_tools_available = FALSE;
}

#
# Test for presence of snmpwalk
#
if ( find_in_path("snmpwalk") ){
  set_kb_item(name: "Tools/Present/snmpwalk", value: TRUE);
  set_kb_item(name: "Tools/Missing/snmpwalk", value: FALSE);
} else {
  set_kb_item(name: "Tools/Missing/snmpwalk", value: TRUE);
  set_kb_item(name: "Tools/Present/snmpwalk", value: FALSE);
  summary = summary + "
Tool:   snmpwalk
Effect: Port scanning based on snmpwalk is not available.
";
  all_tools_available = FALSE;
}

#
# Test for presence of ldapsearch
#
if ( find_in_path("ldapsearch") ){
  set_kb_item(name: "Tools/Present/ldapsearch", value: TRUE);
  set_kb_item(name: "Tools/Missing/ldapsearch", value: FALSE);
} else {
  set_kb_item(name: "Tools/Missing/ldapsearch", value: TRUE);
  set_kb_item(name: "Tools/Present/ldapsearch", value: FALSE);
  summary = summary + "
Tool:   ldapsearch
Effect: Advanced ldap directory checks are not available.
";
  all_tools_available = FALSE;
}

#
# Test for presence of masscan
#
if ( find_in_path("masscan") ) {
  set_kb_item(name: "Tools/Present/masscan", value: TRUE);
  set_kb_item(name: "Tools/Missing/masscan", value: FALSE);
} else {
  set_kb_item(name: "Tools/Missing/masscan", value: TRUE);
  set_kb_item(name: "Tools/Present/masscan", value: FALSE);
  summary = summary + "
Tool:   masscan
Effect: Port scanning based on masscan is not available.
";
  all_tools_available = FALSE;
}

#
# Send final summary as log information if "Silent tool check" is not "yes"
#

silent_check = script_get_preference("Silent tool check");
if (silent_check == "yes")
  exit(0);

if (all_tools_available == FALSE)
  log_message(port: 0, data: summary);
else
  log_message(port: 0, data: "
All checks for presence of scanner tools were successful.
This means they are found and are sufficiently up-to-date.");

exit(0);
