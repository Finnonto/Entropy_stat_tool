import statistic as dp
import csv
import os



base_path = '/mnt/d/analyzed/'
target_path = '/mnt/d/analyzed/'


nf = ['orign','total',"distinct" ]
al = ['clifford','pingli']
pcap = ['MAWI_CAIDA']





title = ['type', 'srcIP', 'dstIP', 'sport', 'dport', 'proto', 'pktLen']
diff_title =['type']
KLD_filename = 'All_KLD.csv'
Pearson_filename = 'All_Pearson.csv'
error_avg_filename = 'All_error_avg.csv'
error_std_filename = 'All_error_std.csv'
error_var_filename = 'All_error_var.csv'
diff_SipDip_filename = 'All_diff_SipDip.csv'
All_KLD = []
All_Pearson = []
All_error_avg = []
All_error_std = []
All_error_var = []
All_diff_SipDip =[]
diff_exact_SipDip = []


for nf_ in nf :

    for p in pcap:
        for al_ in al :
            mydata = dp.data_process(normalization=nf_)
            
            mydata.main(
                    output_name="{0}2exact_{1}_{2}".format(al_,p,nf_),
                    base_filepath="{0}{1}/exact_orign_30/".format(base_path,p),
                    target_filepath="{0}{1}/{2}_orign_30/".format(target_path,p,al_),
                    pcap_namelist= p+'.txt'
            )
                
            
                

            KLD_dict =  dict(
                    srcIP=mydata.cal_average_KL_scipy( mydata.cnt_classify(mydata.deviation_srcIP_value), mydata.cnt_classify([0,]*len(mydata.deviation_srcIP_value)) ),
                    dstIP=mydata.cal_average_KL_scipy( mydata.cnt_classify(mydata.deviation_dstIP_value), mydata.cnt_classify([0,]*len(mydata.deviation_dstIP_value)) ),
                    sport=mydata.cal_average_KL_scipy( mydata.cnt_classify(mydata.deviation_sport_value), mydata.cnt_classify([0,]*len(mydata.deviation_sport_value)) ),
                    dport=mydata.cal_average_KL_scipy( mydata.cnt_classify(mydata.deviation_dport_value), mydata.cnt_classify([0,]*len(mydata.deviation_dport_value)) ),
                    proto=mydata.cal_average_KL_scipy( mydata.cnt_classify(mydata.deviation_proto_value), mydata.cnt_classify([0,]*len(mydata.deviation_proto_value)) ),
                    pktLen=mydata.cal_average_KL_scipy( mydata.cnt_classify(mydata.deviation_pktLen_value), mydata.cnt_classify([0,]*len(mydata.deviation_pktLen_value)) )
                        )

            Pearson_dict =  dict(
                    srcIP=mydata.Pearson( mydata.cnt_classify(mydata.deviation_srcIP_value), mydata.cnt_classify([0,]*len(mydata.deviation_srcIP_value)) ),
                    dstIP=mydata.Pearson( mydata.cnt_classify(mydata.deviation_dstIP_value), mydata.cnt_classify([0,]*len(mydata.deviation_dstIP_value)) ),
                    sport=mydata.Pearson( mydata.cnt_classify(mydata.deviation_sport_value), mydata.cnt_classify([0,]*len(mydata.deviation_sport_value)) ),
                    dport=mydata.Pearson( mydata.cnt_classify(mydata.deviation_dport_value), mydata.cnt_classify([0,]*len(mydata.deviation_dport_value)) ),
                    proto=mydata.Pearson( mydata.cnt_classify(mydata.deviation_proto_value), mydata.cnt_classify([0,]*len(mydata.deviation_proto_value)) ),
                    pktLen=mydata.Pearson( mydata.cnt_classify(mydata.deviation_pktLen_value), mydata.cnt_classify([0,]*len(mydata.deviation_pktLen_value)) )
                        )

            error_stat =  dict(
                    srcIP=mydata.get_ave_sd(mydata.deviation_srcIP_value),
                    dstIP=mydata.get_ave_sd(mydata.deviation_dstIP_value),
                    sport=mydata.get_ave_sd(mydata.deviation_sport_value),
                    dport=mydata.get_ave_sd(mydata.deviation_dport_value),
                    proto=mydata.get_ave_sd(mydata.deviation_pktLen_value),
                    pktLen=mydata.get_ave_sd(mydata.deviation_proto_value),
                        )
            
                
            error_avg = [ 
                mydata.filename_format, error_stat['srcIP'][0], error_stat['dstIP'][0], error_stat['sport'][0], 
                                error_stat['dport'][0], error_stat['proto'][0], error_stat['pktLen'][0]    
            ]   


            error_std =  [ 
                mydata.filename_format, error_stat['srcIP'][1], error_stat['dstIP'][1], error_stat['sport'][1], 
                                error_stat['dport'][1], error_stat['proto'][1], error_stat['pktLen'][1]    
            ]   
            
            error_var =  [ 
                mydata.filename_format, error_stat['srcIP'][2], error_stat['dstIP'][2], error_stat['sport'][2], 
                                error_stat['dport'][2], error_stat['proto'][2], error_stat['pktLen'][2]    
            ]  

            All_error_avg.append(error_avg)
            All_error_std.append(error_std)
            All_error_var.append(error_var)
            KLD_data = [ 
                mydata.filename_format, KLD_dict['srcIP'], KLD_dict['dstIP'], KLD_dict['sport'], 
                                KLD_dict['dport'], KLD_dict['proto'], KLD_dict['pktLen'] 
            ]
            All_KLD.append(KLD_data)

            Pearson_data = [ 
                mydata.filename_format, Pearson_dict['srcIP'], Pearson_dict['dstIP'], Pearson_dict['sport'], 
                                Pearson_dict['dport'], Pearson_dict['proto'], Pearson_dict['pktLen'] 
            ]
            All_Pearson.append(Pearson_data)
            

            All_diff_SipDip.append([al_+'_'+nf_]+mydata.get_difference(mydata.est_srcIP_entropy,mydata.est_dstIP_entropy))
        All_diff_SipDip.append(['exact_'+nf_]+mydata.get_difference(mydata.exact_srcIP_entropy,mydata.exact_dstIP_entropy))


diff_title += [x for x in range(len(mydata.est_dstIP_entropy))]



with open(KLD_filename, 'w', encoding='utf-8') as fout:
            writer = csv.writer(fout, delimiter=',')
            writer.writerow(title)
            
            for data in All_KLD: writer.writerow(data)

with open(Pearson_filename, 'w', encoding='utf-8') as fout:
            writer = csv.writer(fout, delimiter=',')
            writer.writerow(title)
            
            for data in All_Pearson: writer.writerow(data)

with open(error_avg_filename , 'w', encoding='utf-8') as fout:
            writer = csv.writer(fout, delimiter=',')
            writer.writerow(title)
            
            for data in All_error_avg: writer.writerow(data)

with open(error_std_filename , 'w', encoding='utf-8') as fout:
            writer = csv.writer(fout, delimiter=',')
            writer.writerow(title)
            
            for data in All_error_std: writer.writerow(data)            

with open(error_var_filename , 'w', encoding='utf-8') as fout:
            writer = csv.writer(fout, delimiter=',')
            writer.writerow(title)
            
            for data in All_error_var: writer.writerow(data) 


with open(diff_SipDip_filename , 'w', encoding='utf-8') as fout:
            writer = csv.writer(fout, delimiter=',')
            writer.writerow(diff_title)
    
            for data in All_diff_SipDip : writer.writerow(data)             