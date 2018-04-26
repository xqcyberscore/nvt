###############################################################################
# OpenVAS Vulnerability Test support library
# $Id: policy_functions.inc 9613 2018-04-25 15:09:56Z emoss $
#
# Supporting methods for Policy NVTs.
#
# Authors:
# Emanuel Moss <emanuel.moss@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

function policy_logging(text)
{
  # This function is used by basic policy tests. The silence value is set in
  # compliance_tests.nasl. If you start the test within a standard policy like
  # IT-Grundschutz, the results are silent by default. If you start the basic 
  # policy test by themselves, they are verbose.
  local_var verbose, text;
  verbose = get_kb_item("Compliance/verbose");
  if(verbose){
    log_message(data:text, port:0);
  }
}

function policy_set_kb(oid,val){
  local_var oid,val;
  oid = '1.3.6.1.4.1.25623.1.0.' + oid;
  # save as string, because value can be "0", which would lead to not set the kb_entry
  set_kb_item(name:oid, value:string(val));
}

function rsop_securitysettingsboolean(select,keyname,oid){
  local_var select,keyname,oid;

  host = get_host_ip();
  usrname = kb_smb_login();
  passwd  = kb_smb_password();
  domain  = kb_smb_domain();
  if( domain ) usrname = domain + "\" + usrname;

  handle = wmi_connect(host:host, username:usrname, password:passwd, ns:'root\\rsop\\computer');
    if(!handle){
    policy_logging(text:'WMI Connect to host failed.');
    policy_set_kb(oid:oid,val:'error');
    wmi_close(wmi_handle:handle);
    exit(0);
  }
  
  query = "SELECT " + select + " FROM RSOP_SecuritySettingBoolean WHERE KeyName = '" + keyname + "' AND precedence = '1'";
  res = wmi_query_rsop(wmi_handle:handle, query:query);
  splitRes = split(res, sep:"|", keep:FALSE);
  if(max_index(splitRes) < 4){
  	return('');
  }
  returnValue = splitRes[4];

  wmi_close(wmi_handle:handle);
  return(string(returnValue));
}

function rsop_securitysettingsnumeric(select,keyname,oid){
  local_var select,keyname,oid;

  host = get_host_ip();
  usrname = kb_smb_login();
  passwd  = kb_smb_password();
  domain  = kb_smb_domain();
  if( domain ) usrname = domain + "\" + usrname;

  handle = wmi_connect(host:host, username:usrname, password:passwd, ns:'root\\rsop\\computer');
    if(!handle){
    policy_logging(text:'WMI Connect to host failed.');
    policy_set_kb(oid:oid,val:'error');
    wmi_close(wmi_handle:handle);
    exit(0);
  }
  
  query = "SELECT " + select + " FROM RSOP_SecuritySettingNumeric WHERE KeyName = '" + keyname + "' AND precedence = '1'";
  res = wmi_query_rsop(wmi_handle:handle, query:query);
  splitRes = split(res, sep:"|", keep:FALSE);
  if(max_index(splitRes) < 4){
  	return('');
  }
  returnValue = splitRes[4];

  wmi_close(wmi_handle:handle);
  return(string(returnValue));
}