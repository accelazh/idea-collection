1. MonMap 结构很简单，就是
	epoch（整数）
	各个monitor的名字和ip地址

2. 可以研究的东西
	1. lockdep用来检测锁循环
	2. encode机制，有专门的文件encoding.h，用到了ceph::buffe::list

------------------------

1. KeyValueStore这一块
	LevelDBStore中，prefix其实是和key粘在了一起存进去了
	transaction其实是LevelDBStore的Batch操作
	compact指的是合并SSTable，就是LSM-Tree的标准操作
	Leveldb::DB的打开，在LevelDBStore::do_open()中
	MonitorDBStore底层用了LevelDBStore，其构造是文件路径path，在构造函数中传入。

1.1. Mon大量使用MonitorDBStore，即leveldb存储状态信息

2. Messenger这一块
	Dispatcher即指接收消息的人

3. Paxos
	Paxos.h定位是，paxos算法模型+消息发送，数据只是bytes
	PaxosService的定位是，有数据类型的paxos，并提供根据数据类型的一些方法，比如monmap
	尽管难懂，Paxos可以说是最extensively commented的代码了
	dispatch()函数往往是处理流程的核心吗？

   PaxosService->dispatch()->propose_pending()->encode_pending()

	PGMonitor的关键是pending_inc，从encode_pending()中寻找paxos要同步的数据
	OSDMonitor存有crushmap
		tick()中检查OSD状态，和do_propose

	What is MonSession?
	LogMonitor似乎比较简单，适合用来学习
	Tip: 可以通过跟踪state变量的变化，来学习Monitor.cc的代码
	PaxosService的一组类中，似乎不与messenger直接沟通。它们的dispatch()函数由Monitor.cc来调用的，在Monitor::dispatch()中。

4. Paxos规则
	ref: http://duanple.blog.163.com/blog/static/709717672011440267333/
	0. 角色和名词
		Proposer：意为提案者，它可以提出一个提案
		Proposal：提案，由Proposer提出。一个提案由一个编号及value形成的对组成，编号是为了防止混淆保证提案的可区分性，value即代表了提案本身的内容。
		
		Acceptor：是提案的受理者，有权决定是否它本身是否接受该提案
		Choose：提案被选定，在本文中当有半数以上Acceptor接受该提案时，就认为该提案被选定了，被选定的提案
		
		Learner：需要知道被选定的提案信息的那些人

	1. P1: 一个acceptor必须通过(accept)它收到的第一个提案。
	   P1a: 一个acceptor可以接受一个编号为n的提案，只要它还未响应任何编号大于n的prepare请求。

	2. P2: 如果具有value值v的提案被选定(chosen)了，那么所有比它编号更高的被选定的提案的value值也必须是v。
	   P2c: 对于任意的n和v，如果编号为n和value值为v的提案被提出，那么肯定存在一个由半数以上的acceptor组成的集合S，可以满足条件a)或者b)中的一个：
	   a)S中不存在任何的acceptor通过过编号小于n的提案。
	   b)v是S中所有acceptor通过的编号小于n的具有最大编号的提案的value值。
	   
	   P2c决定proposer如何产生proposal
	
	3. proposer如何产生proposal的算法：

		1. proposer选择一个新的提案编号n，然后向某个acceptors集合的成员发送请求，要求acceptor做出如下回应：
			(a).保证不再通过任何编号小于n的提案
			(b).当前它已经通过的编号小于n的最大编号的提案，如果存在的话

		2. 如果proposer收到了来自半数以上的acceptor的响应结果，那么它就可以产生编号为n，value值为v的提案，这里v是所有响应中编号最大的提案的value值，如果响应中不包含任何的提案那么这个值就可以由proposer任意选择。

		我们把这样的一个请求称为编号为n的prepare请求。

		Proposer通过向某个acceptors集合发送需要被通过的提案请求来产生一个提案(此时的acceptors集合不一定是响应prepare阶段请求的那个acceptors集合)。我们称此请求为accept请求。

	4. acceptor如何响应上述算法？

	   Acceptor可以忽略任何请求而不用担心破坏其算法的安全性。
	   Acceptor必须记住这些信息即使是在出错或者重启的情况下。
	   Proposer可以总是可以丢弃提案以及它所有的信息—只要它可以保证不会产生具有相同编号的提案即可。
	
	5.  将proposer和acceptor放在一块，我们可以得到算法的如下两阶段执行过程：

		Phase1.(a) proposer选择一个提案编号n，然后向acceptors的某个majority集合的成员发送编号为n的prepare请求。

		(b).如果一个acceptor收到一个编号为n的prepare请求，且n大于它已经响应的所有prepare请求的编号。那么它就会保证不会再通过(accept)任何编号小于n的提案，同时将它已经通过的最大编号的提案(如果存在的话)作为响应{!?此处隐含了一个结论，最大编号的提案肯定是小于n的}。

		Phase2.(a)如果proposer收到来自半数以上的acceptor对于它的prepare请求(编号为n)的响应，那么它就会发送一个针对编号为n，value值为v的提案的accept请求给acceptors，在这里v是收到的响应中编号最大的提案的值，如果响应中不包含提案，那么它就是任意值。

		(b).如果acceptor收到一个针对编号n的提案的accept请求，只要它还未对编号大于n的prepare请求作出响应，它就可以通过这个提案。	

	6. 很容易构造出一种情况，在该情况下，两个proposers持续地生成编号递增的一系列提案。
	   为了保证进度，必须选择一个特定的proposer来作为一个唯一的提案提出者。

	   如果系统中有足够的组件(proposer，acceptors及通信网络)工作良好，通过选择一个特定的proposer，活性就可以达到。著名的FLP结论指出，一个可靠的proposer选举算法要么利用随机性要么利用实时性来实现—比如使用超时机制。然而，无论选举是否成功，安全性都可以保证。{!即即使同时有2个或以上的proposers存在，算法仍然可以保证正确性}

	7. 不同的proposers会从不相交的编号集合中选择自己的编号，这样任何两个proposers就不会有相同编号的提案了。

	8. 关于leader election算法：http://csrd.aliapp.com/?p=162

-------------------------------------------------

1. monitor的paxos
	1. 所有的数据存在MonitorDBStore中，实际上是leveldb
	2. Paxos <- PaxosService <- MonmapService, OSDService ... <- Monitor

2. Monitor walkthrough
	[Mon0]
	init()
		bootstrap()
			state = STATE_PROBING
			send_message(new MMonProbe(OP_PROBE..)..)
	
	[Mon2]
	dispatch()
		handle_probe_probe()
			send_message(new MMonProbe(OP_REPLY..)..)
					

	[Mon0]
	dispatch()
		handle_proble_reply()
			if newer monmap
				use new monmap
				bootstrap()
			if ...
				bootstrap()
			if paxos->get_version() < m->paxos_first_version && m->paxos_first_version > 1 // my paxos verison is too low
				sync_start()
			if paxos->get_version() + g_conf->paxos_max_join_drift < m->paxos_last_version
				sync_start()
			if I'm part of cluster
				start_election()
			if outside_quorum.size() >= monmap->size() / 2 + 1
				start_election()
				
----------------------------------------------------------
	[election process] 编号小的mon胜利(entity_name_t._num,也是mon->rank)
		1. 每个Elector都向其它人发proposal，申请自己是leader
		2. 每个Elector收到proposal，leader_acked, m->get_source().num(), 自己mon->rank，谁小就defer到谁。
		   defer()会发送OP_ACK消息
		3. 收到ACK的Elector，会检查如果acked_me.size() == mon->monmap->size()，则victory()

	start_election()
		elector.call_election()
			 if (epoch % 2 == 0) 
			    bump_epoch(epoch+1)
			electing_me = true;
			broadcast to all
				send_message(new MMonElection(OP_PROPOSE, epoch, mon->monmap))

	Monitor.dispatch()
		case MSG_MON_ELECTION:
			elector.dispatch(m)
				if (peermap->epoch > mon->monmap->epoch)
					mon->monmap->decode(em->monmap_bl)
					mon->bootstrap()
				 switch (em->op)
					case MMonElection::OP_PROPOSE:
						handle_propose(em)
							if ignoring propose without required features
								nak_old_peer()
								return
							if (m->epoch > epoch)
								bump_epoch()
									mon->join_election()
							if (m->epoch < epoch) // got an "old" propose
								...
								return
							if (mon->rank < from) // i would win over them.
								...
							else 
								defer(from)
									send_message(new MMonElection(OP_ACK, epoch, mon->monmap), from)

	Elector.dispatch()
		case MMonElection::OP_ACK:
			handle_ack(em)
				if (m->epoch > epoch)
					bump_epoch(m->epoch);
    					start()
					return
				if (electing_me) // thanks
					 if (acked_me.size() == mon->monmap->size())
      						victory()
							change cmd set
							for each one
								send_message(new MMonElection(OP_VICTORY, epoch, mon->monmap), mon->monmap->get_inst(*p))
							mon->win_election()
								state = STATE_LEADER
								paxos->leader_init()
								monmon()->election_finished()
								
	Elector.dispatch()
		case MMonElection::OP_VICTORY:
			handle_victory()
				mon->lose_election()
				stash leader's commands


---------------------

1. Mon sync_start() 
/*同步的内容是paxos->get_version(), 整个

*/

[mon0]
sync_start()
	state = STATE_SYNCHRONIZING
	sync_provider = other
	send_message(new MMonSync(sync_full?OP_GET_COOKIE_FULL:OP_GET_COOKIE_RECENT), sync_provider)

[mon1]
dispatch()
	handle_sync_get_cookie()
		MMonSync *reply = new MMonSync(MMonSync::OP_COOKIE, sp.cookie);
  		reply->last_committed = sp.last_committed;
  		messenger->send_message(reply, m->get_connection());

[mon0]
dispatch()
	handle_sync()
		handle_sync_cookie()
			sync_cookie = m->cookie;
  			sync_start_version = m->last_committed;
  			MMonSync *r = new MMonSync(MMonSync::OP_GET_CHUNK, sync_cookie);
  			messenger->send_message(r, sync_provider);

[mon1]
dispatch()
	handle_sync()
		handle_sync_get_chunk()
			MMonSync *reply = new MMonSync(MMonSync::OP_CHUNK, sp.cookie);
			
			MonitorDBStore::Transaction tx;
			tx.put(paxos->get_name(), sp.last_committed, bl);
			sp.synchronizer->get_chunk_tx(tx, left);	// 拷贝整个MonitorDBStore
			::encode(tx, reply->chunk_bl);
			
			if no next chunk
				reply->op = MMonSync::OP_LAST_CHUNK;

			messenger->send_message(reply, m->get_connection());

[mon0]
dispatch()
	handle_sync()
		handle_sync_chunk()
			MonitorDBStore::Transaction tx;
			tx.append_from_encoded(m->chunk_bl);
			store->apply_transaction(tx);

			if OP_LAST_CHUNK
				sync_finish(m->last_committed);
					init_paxos();
					bootstrap();

---------------------------------------------------------

1. Paxos & PaxosService

	1. PaxosService::propose_pending()调用Paxos::propose_new_value()，称作commit。
	   MonmapService之类的都通过propose_ending()实现提交，不需要直接调用propose_new_value()。

	   propose_pending()中调用了encode_pendine()。
	   PaxosService::encode_pending()抽象函数，由子类覆盖。通过它能找到子类负责什么样的数据。

	2. Monitor::preinit()中，调用了
			paxos->init();
			for (int i = 0; i < PAXOS_NUM; ++i) {
				paxos_service[i]->init();
			}

  		Monitor::_reset中，调用了
  			paxos->restart();
  			for (vector<PaxosService*>::iterator p = paxos_service.begin(); p != paxos_service.end(); ++p)
    			(*p)->restart();

  		Monitor::win_election()中，调用了
  			paxos->leader_init()
  			monmon()->election_finished();
			for (vector<PaxosService*>::iterator p = paxos_service.begin(); p != paxos_service.end(); ++p) {
				if (*p != monmon())
					(*p)->election_finished();
			}

  		Monitor::lose_election()中，调用了
  			paxos->peon_init()
  			for (vector<PaxosService*>::iterator p = paxos_service.begin(); p != paxos_service.end(); ++p)
    			(*p)->election_finished();

1.5. Paxos leader collect
	leader_init()
		...
		collect(0);

	[mon0]
	collect(0)   //leader
		state = STATE_RECOVERING;
		
		// look for uncommitted value
  		if (get_store()->exists(get_name(), last_committed+1)) {
  			version_t v = get_store()->get(get_name(), "pending_v");
    		version_t pn = get_store()->get(get_name(), "pending_pn");
    		uncommitted_pn = pn;
    		uncommitted_v = last_committed+1;
    		get_store()->get(get_name(), last_committed+1, uncommitted_value);
    	}

    	// pick new pn
  		accepted_pn = get_new_proposal_number(MAX(accepted_pn, oldpn));

  		// send collect
  		for (set<int>::const_iterator p = mon->get_quorum().begin(); p != mon->get_quorum().end(); ++p) {
		    if (*p == mon->rank) continue;
		    
		    MMonPaxos *collect = new MMonPaxos(mon->get_epoch(), MMonPaxos::OP_COLLECT, ceph_clock_now(g_ceph_context));
		    collect->last_committed = last_committed;
		    collect->first_committed = first_committed;
		    collect->pn = accepted_pn;
		    mon->messenger->send_message(collect, mon->monmap->get_inst(*p));
		}

	[mon1]
	handle_collect()	//peon
		state = STATE_RECOVERING

		MMonPaxos *last = new MMonPaxos(mon->get_epoch(), MMonPaxos::OP_LAST, ceph_clock_now(g_ceph_context));
  		last->last_committed = last_committed;
  		last->first_committed = first_committed;

  		// can we accept this pn?
  		if (collect->pn > accepted_pn) {
  			accepted_pn = collect->pn;
  			MonitorDBStore::Transaction t;
  			t.put(get_name(), "accepted_pn", accepted_pn);
  		}

  		// share whatever committed values we have
  		if (collect->last_committed < last_committed)
    		share_state(last, collect->first_committed, collect->last_committed)	// 把我的过去多个commit放到了last中
    			for ( ; v <= last_committed; v++) {
					if (get_store()->exists(get_name(), v)) {
						get_store()->get(get_name(), v, m->values[v]);
					}
				}
    			m->last_committed = last_committed;

    	// do we have an accepted but uncommitted value?
  		//  (it'll be at last_committed+1)	
  		if (collect->last_committed <= last_committed && get_store()->exists(get_name(), last_committed+1)) {
  			get_store()->get(get_name(), last_committed+1, bl);
  			last->values[last_committed+1] = bl;
  			version_t v = get_store()->get(get_name(), "pending_v");
    		version_t pn = get_store()->get(get_name(), "pending_pn");
    		last->uncommitted_pn = pn;
  		}

  		// send reply
  		mon->messenger->send_message(last, collect->get_source_inst());

  	[mon0]
  	handle_last() 	// leader
  		// store any committed values if any are specified in the message
  		need_refresh = store_state(last);

  		// do they accept your pn?
  		if (last->pn > accepted_pn) {
  			// no, try again
  			collect(last->pn);
  		} else if (last->pn == accepted_pn) {
  			// yes, they do. great!
  			num_last++;

  			// did this person send back an accepted but uncommitted value?
  			if (last->uncommitted_pn) {
		    if (last->uncommitted_pn >= uncommitted_pn && last->last_committed >= last_committed && last->last_committed + 1 >= uncommitted_v) {
		    	// we learned an uncommitted value
				uncommitted_v = last->last_committed+1;
				uncommitted_pn = last->uncommitted_pn;
				uncommitted_value = last->values[uncommitted_v];
		      }
		    }

		    // is that everyone?
		    if (num_last == mon->get_quorum().size()) {
		    	// share committed values?
				for (map<int,version_t>::iterator p = peer_last_committed.begin(); p != peer_last_committed.end(); ++p) {
					if (p->second < last_committed) {
						// share committed values
					MMonPaxos *commit = new MMonPaxos(mon->get_epoch(), MMonPaxos::OP_COMMIT, ceph_clock_now(g_ceph_context));
					share_state(commit, peer_first_committed[p->first], p->second);
					mon->messenger->send_message(commit, mon->monmap->get_inst(p->first));
				}
		    }

		    // did we learn an old value?
      		if (uncommitted_v == last_committed+1 && uncommitted_value.length()) {
				state = STATE_UPDATING_PREVIOUS;
				begin(uncommitted_value);
			} else{
				finish_round();
					state = STATE_ACTIVE
			}

  		} else {
  			// this is an old message, discard
  		}

2. Paxos proposal
	PaxosService::dispatch(m)
		preprocess_query(PaxosServiceMessage* m)
		if (!mon->is_leader()) {
			mon->forward_request_leader(m);
			return true;
		}
		prepare_update(m)
		if (should_propose(delay)) {
      		if (delay == 0.0) {
				propose_pending();
      	}

    [mon0]
	PaxosService::propose_pending()
		Paxos::propose_new_value()
			queue_proposal(bl, onfinished);
			proposed_queued()
				C_Proposal *proposal = static_cast<C_Proposal*>(proposals.front());
				proposal->proposed = true;
				state = STATE_UPDATING;
				begin(proposal->bl);	//leader
					// accept it ourselves
  					accepted.clear();
  					accepted.insert(mon->rank);
  					new_value = v;

  					// store the proposed value in the store.
  					MonitorDBStore::Transaction t;
  					t.put(get_name(), last_committed+1, new_value);
  					t.put(get_name(), "pending_v", last_committed + 1);
  					t.put(get_name(), "pending_pn", accepted_pn);
  					get_store()->apply_transaction(t);

  					// ask others to accept it too!
					for (set<int>::const_iterator p = mon->get_quorum().begin(); p != mon->get_quorum().end(); ++p) {
						if (*p == mon->rank) continue;
						
						MMonPaxos *begin = new MMonPaxos(mon->get_epoch(), MMonPaxos::OP_BEGIN, ceph_clock_now(g_ceph_context));
						begin->values[last_committed+1] = new_value;
						begin->last_committed = last_committed;
						begin->pn = accepted_pn;
						
						mon->messenger->send_message(begin, mon->monmap->get_inst(*p));
					}

					// set timeout event
  					accept_timeout_event = new C_AcceptTimeout(this);
  					mon->timer.add_event_after(g_conf->mon_accept_timeout, accept_timeout_event); // 如果accept长时间未完成，则触发accept_timeout

	[mon1..n]
	handle_begin()	//peon
		if (begin->pn < accepted_pn) {return;}
		state = STATE_UPDATING;

		version_t v = last_committed+1;
		MonitorDBStore::Transaction t;
		t.put(get_name(), v, begin->values[v]);
		t.put(get_name(), "pending_v", v);
  		t.put(get_name(), "pending_pn", accepted_pn);
  		get_store()->apply_transaction(t);

  		MMonPaxos *accept = new MMonPaxos(mon->get_epoch(), MMonPaxos::OP_ACCEPT,
				    ceph_clock_now(g_ceph_context));
	  	accept->pn = accepted_pn;
	  	accept->last_committed = last_committed;
	  	mon->messenger->send_message(accept, begin->get_source_inst());


	[mon0]
	handle_accept()	//leader
		accepted.insert(from);
		// new majority?
		if (accepted.size() == (unsigned)mon->monmap->size()/2+1) {
			commit();
				MonitorDBStore::Transaction t;
				// commit locally
  				last_committed++;
  				last_commit_time = ceph_clock_now(g_ceph_context);
  				t.put(get_name(), "last_committed", last_committed);

  				for (set<int>::const_iterator p = mon->get_quorum().begin(); p != mon->get_quorum().end(); ++p) {
					if (*p == mon->rank) continue;

					MMonPaxos *commit = new MMonPaxos(mon->get_epoch(), MMonPaxos::OP_COMMIT, ceph_clock_now(g_ceph_context));
					commit->values[last_committed] = new_value;
					commit->pn = accepted_pn;
					commit->last_committed = last_committed;
					mon->messenger->send_message(commit, mon->monmap->get_inst(*p));
				}

			do_refresh()  // to notify PaxosService subclasses 
				...
			commit_proposal()
				C_Proposal *proposal = static_cast<C_Proposal*>(proposals.front());
				proposals.pop_front();
				proposal->complete(0);

		// done?
  		if (accepted == mon->get_quorum()) {
  			extend_lease();
  				lease_expire = ceph_clock_now(g_ceph_context);
  				lease_expire += g_conf->mon_lease;
  				acked_lease.clear();
  				acked_lease.insert(mon->rank);

				for (set<int>::const_iterator p = mon->get_quorum().begin(); p != mon->get_quorum().end(); ++p) {
					if (*p == mon->rank) continue;
					
					MMonPaxos *lease = new MMonPaxos(mon->get_epoch(), MMonPaxos::OP_LEASE, ceph_clock_now(g_ceph_context));
					lease->last_committed = last_committed;
					lease->lease_timestamp = lease_expire;
					lease->first_committed = first_committed;
					mon->messenger->send_message(lease, mon->monmap->get_inst(*p));
				}

  			finish_round();
  				state = STATE_ACTIVE;
  		}

  	[mon1..n]
  	handle_commit(MMonPaxos *commit)
  		store_state(commit)
  			start, end = ... // we want to write the range [last_committed, m->last_committed] only.
  			for (it = start; it != end; ++it) {
				t.put(get_name(), it->first, it->second);
				decode_append_transaction(t, it->second);
		    }
		    get_store()->apply_transaction(t);

  		do_refresh()

  	/*
  	I guess
  		last_committed表示paxos算法instance
  		version_t表示一个算法instance内，proposal的编号

  		如果accept长时间未完成，则触发accept_timeout
  		如果peon长时间为达成一致accept，那么extend_lease()就不会为它们执行，它们会发生lease_timeout

  		Monitor所用的paxos似乎是一种改进版的paxos。
  			首先保证有且仅有一个leader。
  			然后phase1只需要在leader初始时运行一次。
  			之后的propose只需要phase2。
  	*/

  	------------------ OP_LEASE process ----------------
  	[mon0]
  	extend_lease();	// extend lease of other mon

  	[mon1..n]
  	handle_lease()
  		lease_expire = lease->lease_timestamp;
  		state = STATE_ACTIVE;

		// ack
		MMonPaxos *ack = new MMonPaxos(mon->get_epoch(), MMonPaxos::OP_LEASE_ACK, ceph_clock_now(g_ceph_context));
		ack->last_committed = last_committed;
		ack->first_committed = first_committed;
		ack->lease_timestamp = ceph_clock_now(g_ceph_context);
		mon->messenger->send_message(ack, lease->get_source_inst());

		// (re)set timeout event.
  		reset_lease_timeout();

  	[mon0]
  	handle_lease_ack()
  		if (acked_lease == mon->get_quorum()) {
      		mon->timer.cancel_event(lease_ack_timeout_event);
      		lease_ack_timeout_event = 0;
      	}

    ---------------- OP_ACCEPT timeout ----------------

    void Paxos::accept_timeout()
		mon->bootstrap();

    -----------------How paxos value is read -----------------

    Paxos::handle_last() or handle_accept() or handle_commit() in the end
    	Paxos::do_refresh()
	    	mon->refresh_from_paxos(&need_bootstrap);
				for (int i = 0; i < PAXOS_NUM; ++i) {
					paxos_service[i]->refresh(need_bootstrap);
						// update cached versions
	  					cached_first_committed = mon->store->get(get_service_name(), first_committed_name);
	  					cached_last_committed = mon->store->get(get_service_name(), last_committed_name);

	  					update_from_paxos(need_bootstrap)			// implemented by subclasses, below use code of MonmapMonitor
	  						version_t version = get_last_committed();
	  						int ret = get_version(version, monmap_bl);	
	  						mon->monmap->decode(monmap_bl);
				}
				for (int i = 0; i < PAXOS_NUM; ++i) {
					paxos_service[i]->post_paxos_update()		// implemented by subclasses, below use code of MonmapMonitor
						// 什么都没写
				}


	/*
		假如不是MonmapMonitor的commit，MonmapMonitor也给refresh了怎么办？
			update_from_paxos()中get_version()对应的put_version()在encode_pending()中。
			get_version()并不是直接从paxos中拿，而是从get(get_service_name(), ver, bl)的get_service_name()中拿
	*/

	----------------- MonClient how to get ----------------

	MonClient::get_monmap()
		_sub_want("monmap", 0, 0);

		 while (want_monmap)
    		map_cond.Wait(monc_lock);

    [MonClient]
    MonClient::_reopen_session()
    	if (!sub_have.empty())
    		_renew_subs();
    			MMonSubscribe *m = new MMonSubscribe;
   				m->what = sub_have;
    			_send_mon_message(m);

    [Monitor]
    dispatch()
    	handle_subscribe()
    		for (map<string,ceph_mon_subscribe_item>::iterator p = m->what.begin(); p != m->what.end(); ++p){
    			session_map.add_update_sub(s, p->first, p->second.start, p->second.flags & CEPH_SUBSCRIBE_ONETIME, m->get_connection()->has_feature(CEPH_FEATURE_INCSUBOSDMAP));
    		}

    [OSDMonitor]
    OSDMonitor::update_from_paxos()
    	check_subs()
    		check_sub()
    			send_incremental(sub->next, sub->session->inst, sub->incremental_onetime);

    [MDSMonitor]
    同OSDMonitor

-------------------------

    [MonClient]
    MonClient::get_monmap_privately()
    	messenger->send_message(new MMonGetMap, cur_con)

    [Monitor]
    dispatch()
    	case CEPH_MSG_MON_GET_MAP:
      		handle_mon_get_map(static_cast<MMonGetMap*>(m));
      			send_latest_monmap(m->get_connection().get());
      				messenger->send_message(new MMonMap(bl), con);

    [MonClient]
    ms_dispatch()
    	case CEPH_MSG_MON_MAP:
    		handle_monmap(static_cast<MMonMap*>(m));
    			::decode(monmap, p);
    			map_cond.Signal();

