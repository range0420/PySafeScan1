
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

module IRISConfig implements DataFlow::ConfigSig {
    // Source: 简化为当前文件下任何函数的参数
    predicate isSource(DataFlow::Node source) {
        source instanceof DataFlow::ParameterNode and
        source.getLocation().getFile().getAbsolutePath().regexpMatch(".*BenchmarkTest00002.*")
    }

    // Sink: 简化为当前文件下任何函数调用
    predicate isSink(DataFlow::Node sink) {
        exists(DataFlow::CallCfgNode c | 
            sink = c.getArg(_) and
            c.getLocation().getFile().getAbsolutePath().regexpMatch(".*BenchmarkTest00002.*")
        )
    }
}

module IRISFlow = TaintTracking::Global<IRISConfig>;

from DataFlow::Node source, DataFlow::Node sink
where IRISFlow::flow(source, sink)
select sink, source.getLocation().toString(), sink.getLocation().toString()
