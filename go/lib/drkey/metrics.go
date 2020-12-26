// Copyright 2021 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package drkey

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"

	dblib "github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/tracing"
)

const (
	svNamespace   = "secretValueDB"
	lvl1Namespace = "drkeyLvl1DB"
	lvl2Namespace = "drkeyLvl2DB"

	promDBName = "db"
)

type promOp string

const (
	promOpGetSV                  promOp = "get_sv"
	promOpInsertSV               promOp = "insert_sv"
	promOpRemoveOutdatedSV       promOp = "remove_outdated_sv"
	promOpGetLvl1Key             promOp = "get_lvl1_key"
	promOpInsertLvl1Key          promOp = "insert_lvl1_key"
	promOpRemoveOutdatedLvl1Keys promOp = "remove_outdated_lvl1_keys"
	promOpGetASHostKey           promOp = "get_as_host_key"
	promOpInsertASHostKey        promOp = "insert_as_host_key"
	promOpGetHostASKey           promOp = "get_host_as_key"
	promOpInsertHostASKey        promOp = "insert_as_host_key"
	promOpGetHostHostKey         promOp = "get_host_host_key"
	promOpInsertHostHostKey      promOp = "insert_host_host_key"
	promOpRemoveOutdatedLvl2Keys promOp = "remove_outdated_lvl2_keys"
)

var (
	queriesSVTotal   *prometheus.CounterVec
	resultsSVTotal   *prometheus.CounterVec
	queriesLvl1Total *prometheus.CounterVec
	resultsLvl1Total *prometheus.CounterVec
	queriesLvl2Total *prometheus.CounterVec
	resultsLvl2Total *prometheus.CounterVec

	initMetricsSVOnce   sync.Once
	initMetricsLvl1Once sync.Once
	initMetricsLvl2Once sync.Once
)

func initMetricsSV() {
	initMetricsSVOnce.Do(func() {
		queriesSVTotal = prom.NewCounterVec(svNamespace, "", "queries_total",
			"Total queries to the SecretValueDB.", []string{promDBName, prom.LabelOperation})
		resultsSVTotal = prom.NewCounterVec(svNamespace, "", "results_total",
			"The results of the SecretValueDB ops.",
			[]string{promDBName, prom.LabelResult, prom.LabelOperation})
	})
}

func initMetricsLvl1() {
	initMetricsLvl1Once.Do(func() {
		queriesLvl1Total = prom.NewCounterVec(lvl1Namespace, "", "queries_total",
			"Total queries to the lvl1DRKeyDB.", []string{promDBName, prom.LabelOperation})
		resultsLvl1Total = prom.NewCounterVec(lvl1Namespace, "", "results_total",
			"The results of the lvl1DRKeyDB ops.",
			[]string{promDBName, prom.LabelResult, prom.LabelOperation})
	})
}

func initMetricsLvl2() {
	initMetricsLvl2Once.Do(func() {
		queriesLvl2Total = prom.NewCounterVec(lvl2Namespace, "", "queries_total",
			"Total queries to the lvl2DRKeyDB.", []string{promDBName, prom.LabelOperation})
		resultsLvl2Total = prom.NewCounterVec(lvl2Namespace, "", "results_total",
			"The results of the lvl2DRKeyDB ops.",
			[]string{promDBName, prom.LabelResult, prom.LabelOperation})
	})
}

// SVWithMetrics wraps the given SecretValueDB into one that also exports metrics.
func SVWithMetrics(dbName string, svdb SecretValueDB) SecretValueDB {
	initMetricsSV()
	labels := prometheus.Labels{promDBName: dbName}
	return &MetricsSVDB{
		db: svdb,
		metrics: &countersSV{
			queriesSVTotal: queriesSVTotal.MustCurryWith(labels),
			resultsSVTotal: resultsSVTotal.MustCurryWith(labels),
		},
	}
}

type countersSV struct {
	queriesSVTotal *prometheus.CounterVec
	resultsSVTotal *prometheus.CounterVec
}

func (c *countersSV) Observe(ctx context.Context, op promOp,
	action func(ctx context.Context) error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, fmt.Sprintf("drkeySVDB.%s", string(op)))
	defer span.Finish()
	c.queriesSVTotal.WithLabelValues(string(op)).Inc()
	err := action(ctx)

	label := dblib.ErrToMetricLabel(err)
	tracing.Error(span, err)
	tracing.ResultLabel(span, label)

	c.resultsSVTotal.WithLabelValues(label, string(op)).Inc()
}

var _ SecretValueDB = (*MetricsSVDB)(nil)

// MetricsSVDB is a SecretValueDB wrapper that exports the counts of operations as
// prometheus metrics
type MetricsSVDB struct {
	db      SecretValueDB
	metrics *countersSV
}

func (db *MetricsSVDB) SetMaxOpenConns(maxOpenConns int) {
	db.db.SetMaxOpenConns(maxOpenConns)
}

func (db *MetricsSVDB) SetMaxIdleConns(maxIdleConns int) {
	db.db.SetMaxIdleConns(maxIdleConns)
}

func (db *MetricsSVDB) Close() error {
	return db.db.Close()
}

func (db *MetricsSVDB) GetSV(ctx context.Context, meta SVMeta) (SV, error) {
	var ret SV
	var err error
	db.metrics.Observe(ctx, promOpGetSV, func(ctx context.Context) error {
		ret, err = db.db.GetSV(ctx, meta)
		return err
	})
	return ret, err
}

func (db *MetricsSVDB) InsertSV(ctx context.Context, sv SV) error {
	var err error
	db.metrics.Observe(ctx, promOpInsertSV, func(ctx context.Context) error {
		err = db.db.InsertSV(ctx, sv)
		return err
	})
	return err
}

func (db *MetricsSVDB) DeleteExpiredSV(ctx context.Context, cutoff time.Time) (int64, error) {
	var ret int64
	var err error
	db.metrics.Observe(ctx, promOpRemoveOutdatedSV, func(ctx context.Context) error {
		ret, err = db.db.DeleteExpiredSV(ctx, cutoff)
		return err
	})
	return ret, err
}

// Lvl1WithMetrics wraps the given Lvl1DRKeyDB into one that also exports metrics.
func Lvl1WithMetrics(dbName string, lvl1db Lvl1DB) Lvl1DB {
	initMetricsLvl1()
	labels := prometheus.Labels{promDBName: dbName}
	return &MetricsLvl1DB{
		db: lvl1db,
		metrics: &countersLvl1{
			queriesLvl1Total: queriesLvl1Total.MustCurryWith(labels),
			resultsLvl1Total: resultsLvl1Total.MustCurryWith(labels),
		},
	}
}

type countersLvl1 struct {
	queriesLvl1Total *prometheus.CounterVec
	resultsLvl1Total *prometheus.CounterVec
}

func (c *countersLvl1) Observe(ctx context.Context, op promOp,
	action func(ctx context.Context) error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, fmt.Sprintf("drkeyLvl1DB.%s", string(op)))
	defer span.Finish()
	c.queriesLvl1Total.WithLabelValues(string(op)).Inc()
	err := action(ctx)

	label := dblib.ErrToMetricLabel(err)
	tracing.Error(span, err)
	tracing.ResultLabel(span, label)

	c.resultsLvl1Total.WithLabelValues(label, string(op)).Inc()
}

var _ Lvl1DB = (*MetricsLvl1DB)(nil)

// MetricsLvl1DB is a Lvl1DB wrapper that exports the counts of operations as prometheus metrics
type MetricsLvl1DB struct {
	db      Lvl1DB
	metrics *countersLvl1
}

func (db *MetricsLvl1DB) SetMaxOpenConns(maxOpenConns int) {
	db.db.SetMaxOpenConns(maxOpenConns)
}

func (db *MetricsLvl1DB) SetMaxIdleConns(maxIdleConns int) {
	db.db.SetMaxIdleConns(maxIdleConns)
}

func (db *MetricsLvl1DB) Close() error {
	return db.db.Close()
}

func (db *MetricsLvl1DB) GetLvl1Key(ctx context.Context, meta Lvl1Meta) (Lvl1Key, error) {
	var ret Lvl1Key
	var err error
	db.metrics.Observe(ctx, promOpGetLvl1Key, func(ctx context.Context) error {
		ret, err = db.db.GetLvl1Key(ctx, meta)
		return err
	})
	return ret, err
}

func (db *MetricsLvl1DB) InsertLvl1Key(ctx context.Context, key Lvl1Key) error {
	var err error
	db.metrics.Observe(ctx, promOpInsertLvl1Key, func(ctx context.Context) error {
		err = db.db.InsertLvl1Key(ctx, key)
		return err
	})
	return err
}

func (db *MetricsLvl1DB) DeleteExpiredLvl1Keys(ctx context.Context,
	cutoff time.Time) (int64, error) {
	var ret int64
	var err error
	db.metrics.Observe(ctx, promOpRemoveOutdatedLvl1Keys, func(ctx context.Context) error {
		ret, err = db.db.DeleteExpiredLvl1Keys(ctx, cutoff)
		return err
	})
	return ret, err
}

// Lvl2WithMetrics wraps the given Lvl2DRKeyDB into one that also exports metrics.
func Lvl2WithMetrics(dbName string, lvl2db Lvl2DB) Lvl2DB {
	initMetricsLvl2()
	labels := prometheus.Labels{promDBName: dbName}
	return &MetricsLvl2DB{
		db: lvl2db,
		metrics: &countersLvl2{
			queriesLvl2Total: queriesLvl2Total.MustCurryWith(labels),
			resultsLvl2Total: resultsLvl2Total.MustCurryWith(labels),
		},
	}
}

type countersLvl2 struct {
	queriesLvl2Total *prometheus.CounterVec
	resultsLvl2Total *prometheus.CounterVec
}

func (c *countersLvl2) Observe(ctx context.Context, op promOp,
	action func(ctx context.Context) error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, fmt.Sprintf("drkeyLvl2DB.%s", string(op)))
	defer span.Finish()
	c.queriesLvl2Total.WithLabelValues(string(op)).Inc()
	err := action(ctx)

	label := dblib.ErrToMetricLabel(err)
	tracing.Error(span, err)
	tracing.ResultLabel(span, label)

	c.resultsLvl2Total.WithLabelValues(label, string(op)).Inc()
}

var _ Lvl2DB = (*MetricsLvl2DB)(nil)

// MetricsLvl2DB is a Lvl2DB wrapper that exports the counts of operations as prometheus metrics
type MetricsLvl2DB struct {
	db      Lvl2DB
	metrics *countersLvl2
}

func (db *MetricsLvl2DB) SetMaxOpenConns(maxOpenConns int) {
	db.db.SetMaxOpenConns(maxOpenConns)
}

func (db *MetricsLvl2DB) SetMaxIdleConns(maxIdleConns int) {
	db.db.SetMaxIdleConns(maxIdleConns)
}

func (db *MetricsLvl2DB) Close() error {
	return db.db.Close()
}

func (db *MetricsLvl2DB) GetASHostKey(ctx context.Context, meta ASHostMeta) (ASHostKey, error) {
	var ret ASHostKey
	var err error
	db.metrics.Observe(ctx, promOpGetASHostKey, func(ctx context.Context) error {
		ret, err = db.db.GetASHostKey(ctx, meta)
		return err
	})
	return ret, err
}

func (db *MetricsLvl2DB) InsertASHostKey(ctx context.Context, key ASHostKey) error {
	var err error
	db.metrics.Observe(ctx, promOpInsertASHostKey, func(ctx context.Context) error {
		err = db.db.InsertASHostKey(ctx, key)
		return err
	})
	return err
}

func (db *MetricsLvl2DB) GetHostASKey(ctx context.Context, meta HostASMeta) (HostASKey, error) {
	var ret HostASKey
	var err error
	db.metrics.Observe(ctx, promOpGetHostASKey, func(ctx context.Context) error {
		ret, err = db.db.GetHostASKey(ctx, meta)
		return err
	})
	return ret, err
}

func (db *MetricsLvl2DB) InsertHostASKey(ctx context.Context, key HostASKey) error {
	var err error
	db.metrics.Observe(ctx, promOpInsertHostASKey, func(ctx context.Context) error {
		err = db.db.InsertHostASKey(ctx, key)
		return err
	})
	return err
}

func (db *MetricsLvl2DB) GetHostHostKey(ctx context.Context,
	meta HostHostMeta) (HostHostKey, error) {
	var ret HostHostKey
	var err error
	db.metrics.Observe(ctx, promOpGetHostHostKey, func(ctx context.Context) error {
		ret, err = db.db.GetHostHostKey(ctx, meta)
		return err
	})
	return ret, err
}

func (db *MetricsLvl2DB) InsertHostHostKey(ctx context.Context, key HostHostKey) error {
	var err error
	db.metrics.Observe(ctx, promOpInsertHostHostKey, func(ctx context.Context) error {
		err = db.db.InsertHostHostKey(ctx, key)
		return err
	})
	return err
}

func (db *MetricsLvl2DB) DeleteExpiredLvl2Keys(ctx context.Context,
	cutoff time.Time) (int64, error) {
	var ret int64
	var err error
	db.metrics.Observe(ctx, promOpRemoveOutdatedLvl2Keys, func(ctx context.Context) error {
		ret, err = db.db.DeleteExpiredLvl2Keys(ctx, cutoff)
		return err
	})
	return ret, err
}
